//! # Named Entity Recognition (NER)
//!
//! Detects PII spans within plain-text strings using compiled regex patterns
//! with post-match validation where standards apply.
//!
//! The public [`Ner`] trait is deliberately thin so that a real ML-backed
//! recogniser (e.g. a local ONNX model) can be swapped in without touching
//! any caller.
//!
//! ## Standards Compliance
//!
//! | Type       | Standard          | Notes                                          |
//! |------------|-------------------|------------------------------------------------|
//! | Email      | RFC 5322 (subset) | Handles 99%+ of real addresses; skips quoted locals |
//! | CreditCard | ISO/IEC 7812      | Luhn checksum validated after regex match      |
//! | SSN        | SSA format        | Filters invalid area numbers (000, 666, 900+)  |
//! | Phone      | NANP + E.164      | US/CA formats and international compact/formatted |
//! | IPv4       | RFC 791           | Octet range 0–255 validated in regex           |
//!
//! ## Detection Priority
//!
//! To avoid overlapping spans, patterns are applied in this order (highest
//! to lowest priority):
//!
//! 1. Email — prevents name false-positives inside email addresses
//! 2. CreditCard — before SSN to avoid partial 9-digit matches
//! 3. SSN — specific dash-separated format
//! 4. Phone (NANP) — US/Canada formats
//! 5. Phone (international) — E.164 compact and formatted
//! 6. IpAddress — dotted-quad notation
//! 7. JwtToken — three-part base64url form
//! 8. AwsKey — AKIA-prefixed access key IDs
//! 9. EnvSecret — `KEY=value` / `key: value` secret assignments
//! 10. Custom rules — user-defined patterns from `.airlock.toml`
//! 11. Name — last; uses three strategies with a bundled name dictionary
//!
//! ## Name Detection Strategy
//!
//! Names are detected by three complementary strategies (see `detect_names`):
//!
//! | Strategy | Signal | Example | Dictionary check? |
//! |----------|--------|---------|-------------------|
//! | Title-triggered | Honorific prefix | `Dr. Alice Johnson` | No — title is sufficient |
//! | Label-triggered | Field label | `name: Bob Smith` | No — label is sufficient |
//! | Verb-triggered | Attribution verb | `named Emily Davis` | First word must be a known name |
//! | Dictionary | First+last name lists | `Robert Brown` | Yes — full match required |
//!
//! False positives on geographic sequences (`Victoria Park`), company names
//! (`General Electric`), and calendar words are suppressed by `is_non_person_word`.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;
use tracing::debug;

use crate::types::{EntityType, PiiSpan};

// ── Static regex singletons ───────────────────────────────────────────────────

fn email_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
            .expect("static regex is valid")
    })
}

fn credit_card_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Visa (4xxx), Mastercard (5[1-5]xx), Discover (6011/65xx): 16-digit 4-4-4-4
    // Amex (3[47]xx): 15-digit 4-6-5
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}|3[47]\d{2}[- ]?\d{6}[- ]?\d{5})\b",
        )
        .expect("static regex is valid")
    })
}

fn ssn_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // NNN-NN-NNNN format. Invalid area numbers (000, 666, 900-999) are filtered
    // by ssn_valid() after the match since the regex crate lacks lookahead.
    RE.get_or_init(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("static regex is valid"))
}

fn phone_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // NANP: (555) 867-5309, 555-867-5309, +1 555.867.5309
    // Area code starts 2-9 to reduce false positives in version numbers etc.
    RE.get_or_init(|| {
        Regex::new(r"\b(?:\+?1[\s.\-]?)?\(?[2-9]\d{2}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b")
            .expect("static regex is valid")
    })
}

fn international_phone_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // E.164 compact:    +447911123456, +14155551234
    // E.164 formatted:  +44 7911 123456, +49 30 12345678, +1 415 555 1234
    // Country code 1–4 digits; total 10–15 digits per E.164 standard.
    RE.get_or_init(|| {
        Regex::new(r"\+[1-9]\d{9,13}\b|\+[1-9]\d{0,3}[\s.\-]\d{2,9}(?:[\s.\-]\d{2,9}){0,4}\b")
            .expect("static regex is valid")
    })
}

fn ipv4_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Matches valid dotted-quad IPv4 addresses (each octet 0-255)
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
        )
        .expect("static regex is valid")
    })
}

// ── Name detection infrastructure ────────────────────────────────────────────
//
// Name detection uses three complementary strategies, applied in order:
//
//   1. Title-triggered  — "Mr. Smith", "Dr. Alice Johnson"
//      Any capitalised word(s) immediately following an honorific.
//      No dictionary check required — the title is an unambiguous signal.
//
//   2. Label/verb-triggered — "name: Bob Martinez", "named Emily Davis"
//      A field label or attribution verb followed by capitalised word(s).
//      Verb context ("named", "called") requires the first captured word to
//      be in the name dictionary to guard against "called Google Home" etc.
//
//   3. Dictionary-based   — "Robert Brown", "Alice Chen"
//      Two or more consecutive capitalised words scored against bundled
//      first-name and last-name lists.  Three confidence tiers:
//
//        High   first word ∈ first_names  AND  last word ∈ last_names
//        Medium first word ∈ first_names  AND  second word ∉ non_person_words
//               (two-word sequences only)
//        Long   first word ∈ first_names  AND  sequence is 3+ words
//               (longer sequences are extremely rarely non-names)
//
// Words that are non-person second words (geographic, org, calendar) are
// tracked in `is_non_person_word` to suppress false positives like
// "Victoria Park" or "Alice January".

// ── Name dictionaries ─────────────────────────────────────────────────────────

/// Common given names (lowercase). Covers top ~250 US male + female names.
const FIRST_NAMES: &[&str] = &[
    // Male — full forms
    "james","john","robert","michael","william","david","richard","joseph",
    "thomas","charles","christopher","daniel","matthew","anthony","mark",
    "donald","steven","paul","andrew","kenneth","george","joshua","kevin",
    "brian","edward","ronald","timothy","jason","jeffrey","ryan","jacob",
    "gary","nicholas","eric","stephen","jonathan","larry","justin","scott",
    "brandon","frank","benjamin","gregory","samuel","raymond","patrick",
    "alexander","jack","dennis","jerry","tyler","aaron","henry","adam",
    "douglas","nathan","peter","zachary","kyle","walter","harold","jeremy",
    "ethan","carl","keith","roger","gerald","christian","terry","sean",
    "austin","arthur","noah","lawrence","jesse","joe","bryan","billy",
    "jordan","albert","dylan","bruce","gabriel","alan","juan","logan",
    "wayne","ralph","roy","eugene","randy","vincent","russell","elijah",
    "louis","philip","bobby","bradley","liam","oliver","lucas","mason",
    "leo","hunter","carter","eli","owen","caleb","ian","luke","evan",
    "max","simon","marcus","reginald","leonard","barry","travis","chad",
    "dean","derek","cody","brent","marvin","ted","warren","floyd",
    "clarence","clifford","fredrick","gilbert","jerome","leroy","melvin",
    "roland","ronnie","virgil","alvin","wendell","kirk","lance","emmett",
    "salvador","sergio","mario","miguel","carlos","luis","pedro","jorge",
    "manuel","antonio","francisco","jose","roberto","alejandro","hector",
    // Male — common nicknames (often appear without the full given name)
    "bob","mike","tom","bill","jim","dave","sam","ben","rob","dan","tim",
    "ron","don","ken","chris","tony","pat","nick","matt","steve","andy",
    "pete","rick","chuck","hank","theo","jake","zach","brad","drew","fred",
    "hal","herb","jed","lenny","mick","ned","norm","phil","rich","russ",
    "sid","stan","stu","vince","walt","wes","zak",
    // Female
    "mary","patricia","jennifer","linda","barbara","elizabeth","susan",
    "jessica","sarah","karen","lisa","nancy","betty","margaret","sandra",
    "ashley","dorothy","kimberly","emily","donna","michelle","carol",
    "amanda","melissa","deborah","stephanie","rebecca","sharon","laura",
    "cynthia","kathleen","amy","angela","shirley","anna","brenda","pamela",
    "emma","nicole","helen","samantha","katherine","christine","debra",
    "rachel","carolyn","janet","catherine","maria","heather","diane",
    "julie","joyce","victoria","kelly","christina","lauren","joan","evelyn",
    "judith","megan","cheryl","andrea","hannah","martha","jacqueline",
    "frances","gloria","teresa","ann","kathryn","sara","janice","alice",
    "jean","danielle","marilyn","beverly","amber","theresa","doris",
    "madison","denise","ruby","wanda","bonnie","grace","dawn","brooke",
    "crystal","taylor","natalie","brianna","sophia","vanessa","hazel",
    "alexis","tiffany","leah","violet","claire","audrey","diana","abigail",
    "valerie","vivian","ruth","irene","marie","ana","rosa","florence",
    "sylvia","lois","vera","carla","connie","gina","lydia","miranda",
    "priscilla","elaine","charlene","nadine","kayla","holly","tracy",
    "wendy","cindy","sandy","brandy","melody","destiny","avery","morgan",
    "quinn","ariana","allison","alicia","alyssa","brittany","courtney",
    "tara","robyn","giselle","selena","erica","tanya","sherry","jade",
    "sage","ivy","iris","rose","aurora","luna","stella","eleanor","nora",
    "chloe","zoe","lily","maya","aria","scarlett","ellie","mia","ella",
    "eva","addison","layla","penelope","paisley","aaliyah","savannah",
    "autumn","hailey","leila","naomi","phoebe","tabitha","willow","yolanda",
    "jasmine","fiona","beatrice","cecilia","claudia","gwen","bella","olivia",
    "natasha","monique","ebony","latoya","april","june","summer","autumn",
    "charity","faith","hope","grace","joy","mercy","honor","dawn","iris",
    "celeste","marina","valentina","gabriela","lucia","ana","isabella",
    "carmen","elena","sofia","diana","adriana","veronica","monica","rosa",
    "camille","suzanne","colette","renee","simone","brigitte","genevieve",
];

/// Common surnames (lowercase). Covers top ~300 US family names.
const LAST_NAMES: &[&str] = &[
    "smith","johnson","williams","brown","jones","garcia","miller","davis",
    "rodriguez","martinez","hernandez","lopez","gonzalez","wilson","anderson",
    "thomas","taylor","moore","jackson","martin","lee","perez","thompson",
    "white","harris","sanchez","clark","ramirez","lewis","robinson","walker",
    "young","allen","king","wright","scott","torres","nguyen","hill","flores",
    "green","adams","nelson","baker","hall","rivera","campbell","mitchell",
    "carter","roberts","gomez","phillips","evans","turner","diaz","parker",
    "cruz","edwards","collins","reyes","stewart","morris","morales","murphy",
    "cook","rogers","gutierrez","ortiz","morgan","cooper","peterson","bailey",
    "reed","kelly","howard","ramos","kim","cox","ward","richardson","watson",
    "brooks","chavez","wood","james","bennett","gray","mendoza","ruiz",
    "hughes","price","alvarez","castillo","sanders","patel","myers","long",
    "ross","foster","jimenez","powell","jenkins","perry","russell","sullivan",
    "bell","coleman","butler","henderson","barnes","gonzales","fisher",
    "vasquez","simmons","romero","jordan","patterson","alexander","hamilton",
    "graham","reynolds","griffin","wallace","moreno","west","cole","hayes",
    "bryant","herrera","gibson","ellis","tran","medina","aguilar","stevens",
    "murray","ford","castro","marshall","owens","harrison","fernandez",
    "mcdonald","woods","washington","kennedy","wells","vargas","henry",
    "chen","freeman","webb","tucker","guzman","burns","crawford","olson",
    "simpson","porter","hunter","gordon","mendez","silva","shaw","snyder",
    "mason","dixon","munoz","hunt","hicks","holmes","palmer","wagner",
    "black","robertson","boyd","rose","stone","salazar","fox","warren",
    "mills","meyer","rice","schmidt","garza","daniels","ferguson","nichols",
    "stephens","soto","weaver","ryan","gardner","payne","grant","dunn",
    "kelley","spencer","hawkins","arnold","pierce","vazquez","hansen",
    "peters","santos","hart","bradley","knight","elliott","cunningham",
    "duncan","armstrong","hudson","carroll","lane","riley","andrews",
    "alvarado","ray","delgado","berry","perkins","hoffman","johnston",
    "matthews","pena","harvey","burton","chang","cohen","cross","frank",
    "kaiser","klein","lamb","lowe","lynch","malone","mann","maxwell",
    "mcbride","mccoy","mckenzie","mckinney","miles","montgomery","moon",
    "morrison","moss","norris","obrien","oconnor","powers","quinn","ramsey",
    "reid","rowe","sharp","shields","singleton","sloan","snow","stanley",
    "stark","underwood","wade","walsh","walton","watts","wyatt","george",
    "hayes","hudson","strong","terry","cross","obrien","sharp","snow",
    "barker","bates","bond","booth","butler","carr","day","dean","drake",
    "dunn","fox","frost","gill","hart","hill","hunt","lamb","lane",
    "law","love","mann","marsh","nash","page","pope","reed","shaw",
    "wade","ward","wolf","wood","york","best","bird","black","blake",
    "bloom","burns","bush","byrd","cash","cole","cook","cook","crain",
    "crane","crow","daly","dash","dean","dove","duke","dunn","earl",
    "fern","finn","ford","fort","frey","fry","gale","goss","hale",
    "hall","holt","horn","hoyt","hyde","jett","kane","kay","kent",
    "keys","king","kirby","knox","kyle","lake","lara","lark","leal",
    "lott","love","luna","lyons","mack","wade","vance","vega","vera",
];

fn first_name_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| FIRST_NAMES.iter().copied().collect())
}

fn last_name_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| LAST_NAMES.iter().copied().collect())
}

// ── Name-detection regexes ────────────────────────────────────────────────────

/// Honorific + one-or-more capitalised words.
/// Capture group 1 = the name portion (title is non-capturing).
///
/// IMPORTANT: `(?i:...)` scopes case-insensitivity to the title keyword only.
/// The name capture group `([A-Z][a-z]+...)` remains case-sensitive so that
/// `[A-Z]` only matches an uppercase letter and `[a-z]+` only matches
/// lowercase — preventing "Smith was discharged" from being swallowed whole
/// by a greedy case-insensitive `[a-z]+`.
fn title_name_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?i:mr|mrs|ms|miss|dr|prof|professor|rev|reverend|sir|mx|fr|father)\.?\s+([A-Z][a-z]+(?:[\s\-][A-Z][a-z]+)*)",
        )
        .expect("static regex is valid")
    })
}

/// Field label (e.g. `name:`, `patient:`) followed by capitalised words.
/// Capture group 1 = the name portion.
/// Same scoped-(?i:) approach as `title_name_regex`.
fn label_name_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?i:full[\s_]?name|name|first[\s_]?name|last[\s_]?name|surname|username|user|patient|employee|contact|author|physician|nurse|technician|customer|client|owner|manager|director|officer|assignee|reporter|requestor|recipient|provider|sender)\s*:\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)",
        )
        .expect("static regex is valid")
    })
}

/// Attribution verbs ("named X", "called X") followed by capitalised words.
/// Capture group 1 = the name portion.
/// A light dictionary check is applied in `detect_names` to suppress
/// false positives like "called Google Home".
fn verb_context_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?i:named|called)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)")
            .expect("static regex is valid")
    })
}

/// Two or more consecutive capitalised words, used for the dictionary strategy.
fn cap_seq_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b").expect("static regex is valid")
    })
}

// ── False-positive guard ──────────────────────────────────────────────────────

/// Returns `true` when `word` (still in its original capitalised form) is
/// unlikely to be a person's surname regardless of what precedes it.
///
/// Applied to the *second* word in two-word sequences under the medium-confidence
/// dictionary path only.  Title and label signals bypass this check entirely.
fn is_non_person_word(word: &str) -> bool {
    matches!(
        word,
        // Geographic
        "Street" | "Avenue" | "Road" | "Boulevard" | "Lane" | "Drive"
        | "Way" | "Court" | "Place" | "Park" | "Square" | "Plaza"
        | "Circle" | "Heights" | "Hills" | "Valley" | "Lake" | "River"
        | "Mountain" | "Beach" | "Island" | "Bay" | "Bridge" | "Station"
        | "Airport" | "Harbor" | "Port" | "Falls" | "Canyon" | "Creek"
        // Organisation suffixes
        | "Inc" | "Llc" | "Ltd" | "Corp" | "Co" | "Company" | "Group"
        | "University" | "College" | "School" | "Institute" | "Academy"
        | "Hospital" | "Clinic" | "Center" | "Centre" | "Foundation"
        | "Society" | "Association" | "Bank" | "Fund" | "Partners"
        | "Services" | "Solutions" | "Technologies" | "Systems"
        // Directional / common modifiers that open place names
        | "New" | "Old" | "North" | "South" | "East" | "West"
        | "Upper" | "Lower" | "Greater" | "Little" | "Grand" | "Big"
        | "International" | "National" | "American" | "Federal"
        | "State" | "City" | "County" | "District" | "Central" | "Global"
        // Calendar months (rarely surnames; "April" / "June" guarded on
        // the first-name side instead)
        | "January" | "February" | "March" | "April" | "June"
        | "July" | "August" | "September" | "October" | "November" | "December"
        // Weekdays
        | "Monday" | "Tuesday" | "Wednesday" | "Thursday" | "Friday"
        | "Saturday" | "Sunday"
    )
}

// ── Core name detection ───────────────────────────────────────────────────────

/// Run all three name-detection strategies and return the resulting spans.
///
/// `existing` contains spans already claimed by higher-priority detectors
/// (email, credit card, etc.).  Both `existing` and the spans being built
/// are checked to prevent overlaps.
fn detect_names(text: &str, existing: &[PiiSpan]) -> Vec<PiiSpan> {
    let mut spans: Vec<PiiSpan> = Vec::new();
    let first_names = first_name_set();
    let last_names = last_name_set();

    // Inline helper — checks both existing and in-progress spans.
    // The immutable borrow of `spans` inside `overlaps_existing` ends
    // before the mutable `spans.push` below (NLL), so this compiles fine.
    macro_rules! push {
        ($start:expr, $end:expr, $text:expr) => {{
            let s = $start;
            let e = $end;
            if !overlaps_existing(existing, s, e) && !overlaps_existing(&spans, s, e) {
                debug!("NER[Name] {:?} {}..{}", $text, s, e);
                spans.push(PiiSpan {
                    entity_type: EntityType::Name,
                    start: s,
                    end: e,
                    text: ($text).to_owned(),
                });
            }
        }};
    }

    // ── Strategy 1: title-triggered ───────────────────────────────────────
    // "Mr. Smith", "Dr. Alice Johnson", "Prof. Williams"
    // No dictionary check — the honorific is an unambiguous signal.
    for cap in title_name_regex().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            push!(m.start(), m.end(), m.as_str());
        }
    }

    // ── Strategy 2a: label-triggered ──────────────────────────────────────
    // "name: Alice Johnson", "patient: Bob Smith", "employee: Carlos Rivera"
    for cap in label_name_regex().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            push!(m.start(), m.end(), m.as_str());
        }
    }

    // ── Strategy 2b: verb-context-triggered ───────────────────────────────
    // "named Alice Johnson", "called Bob Smith"
    // Light dictionary check: first word must be a known first or last name
    // to suppress "called Google Home", "named Bluetooth Device", etc.
    for cap in verb_context_regex().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            let first_lc = m
                .as_str()
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_lowercase();
            if first_names.contains(first_lc.as_str())
                || last_names.contains(first_lc.as_str())
            {
                push!(m.start(), m.end(), m.as_str());
            }
        }
    }

    // ── Strategy 3: dictionary-based (no explicit context) ────────────────
    // Requires 2+ capitalised words and at least one dictionary match.
    for m in cap_seq_regex().find_iter(text) {
        let seq = m.as_str();
        let words: Vec<&str> = seq.split_whitespace().collect();
        // words.len() >= 2 is guaranteed by cap_seq_regex
        let first_lc = words[0].to_lowercase();
        let last_lc = words[words.len() - 1].to_lowercase();

        let is_name = if first_names.contains(first_lc.as_str())
            && last_names.contains(last_lc.as_str())
        {
            // High confidence: both ends of the sequence are in our dictionaries.
            true
        } else if words.len() == 2
            && first_names.contains(first_lc.as_str())
            && !is_non_person_word(words[1])
        {
            // Medium confidence: first word is a known given name and the
            // second word is not a known geographic/org/calendar term.
            true
        } else if words.len() >= 3 && first_names.contains(first_lc.as_str()) {
            // Long-sequence confidence: three or more capitalised words
            // starting with a known given name are almost never non-names.
            true
        } else {
            false
        };

        if is_name {
            push!(m.start(), m.end(), seq);
        }
    }

    spans
}

fn jwt_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Three base64url segments separated by dots: header.payload.signature
    // Header and payload both decode to JSON, so they start with `eyJ` (base64 of `{"`).
    RE.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_\-]{2,}\.eyJ[A-Za-z0-9_\-]{2,}\.[A-Za-z0-9_\-]{2,}\b")
            .expect("static regex is valid")
    })
}

fn aws_key_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // AWS access key IDs begin with AKIA followed by 16 uppercase alphanumerics.
    RE.get_or_init(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("static regex is valid"))
}

fn env_secret_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Matches `KEY=value` or `key: value` where the key name strongly implies a secret.
    // Capture group 1 isolates the value so the key name is preserved in the output.
    // The value must be at least 6 non-whitespace characters to filter out placeholders.
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|private[_-]?key|password|passwd|db[_-]?pass(?:word)?|auth[_-]?token|access[_-]?token|refresh[_-]?token)\s*[=:]\s*['"]?([^\s'"]{6,})['"]?"#,
        )
        .expect("static regex is valid")
    })
}

// ── Post-match validators ─────────────────────────────────────────────────────

/// Validate a credit card number using the Luhn algorithm (ISO/IEC 7812).
///
/// Delegates to the [`luhn`] crate, which strips spaces and dashes automatically.
fn luhn_valid(s: &str) -> bool {
    luhn::valid(s)
}

/// Validate an SSN area number — rejects 000, 666, and 900-999.
///
/// The regex crate lacks lookahead, so this runs as a post-match filter.
fn ssn_valid(s: &str) -> bool {
    let area: u32 = s[..3].parse().unwrap_or(0);
    area != 0 && area != 666 && area < 900
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Pluggable named-entity recogniser interface.
///
/// Implementors scan a string slice and return all PII [`PiiSpan`]s, sorted
/// by `start` byte offset with no overlapping spans.
pub trait Ner: Send + Sync {
    fn find_spans(&self, text: &str) -> Vec<PiiSpan>;
}

// ── Custom rule ───────────────────────────────────────────────────────────────

/// A compiled custom PII rule loaded from `.airlock.toml`.
pub struct CompiledCustomRule {
    pub name: String,
    pub alias_prefix: String,
    pub pattern: Regex,
}

// ── RegexNer ──────────────────────────────────────────────────────────────────

/// The default regex-based named-entity recogniser.
///
/// All built-in entity types are enabled by default. Set a flag to `false` to
/// skip that detection pass entirely — useful when combined with the
/// `[redact]` section of `.airlock.toml`.
///
/// # Examples
///
/// ```
/// use airlock::ner::{Ner, RegexNer};
///
/// let ner = RegexNer::default();
/// let spans = ner.find_spans("Contact alice@corp.com or call 555-867-5309");
/// assert_eq!(spans.len(), 2);
/// ```
pub struct RegexNer {
    /// User-defined patterns added via `.airlock.toml` `[[rules]]`.
    pub custom_rules: Vec<CompiledCustomRule>,
    /// Detect full names (e.g. `Alice Johnson`). Default: `true`.
    pub names: bool,
    /// Detect email addresses. Default: `true`.
    pub emails: bool,
    /// Detect US phone numbers. Default: `true`.
    pub phones: bool,
    /// Detect Social Security Numbers. Default: `true`.
    pub ssns: bool,
    /// Detect credit card numbers. Default: `true`.
    pub credit_cards: bool,
    /// Detect IPv4 addresses. Default: `true`.
    pub ip_addresses: bool,
    /// Detect JWT tokens (three-part base64url). Default: `true`.
    pub jwt_tokens: bool,
    /// Detect AWS access key IDs (`AKIA…`). Default: `true`.
    pub aws_keys: bool,
    /// Detect secret values in `KEY=value` / `key: value` assignments. Default: `true`.
    pub env_secrets: bool,
}

impl Default for RegexNer {
    fn default() -> Self {
        Self {
            custom_rules: Vec::new(),
            names: true,
            emails: true,
            phones: true,
            ssns: true,
            credit_cards: true,
            ip_addresses: true,
            jwt_tokens: true,
            aws_keys: true,
            env_secrets: true,
        }
    }
}

impl Ner for RegexNer {
    fn find_spans(&self, text: &str) -> Vec<PiiSpan> {
        let mut spans: Vec<PiiSpan> = Vec::new();

        macro_rules! push_spans {
            ($regex:expr, $etype:expr) => {
                push_spans!($regex, $etype, |_: &str| true)
            };
            ($regex:expr, $etype:expr, $validate:expr) => {
                for m in $regex().find_iter(text) {
                    if !overlaps_existing(&spans, m.start(), m.end()) && $validate(m.as_str()) {
                        debug!(
                            "NER[{}] {:?} {}..{}",
                            $etype,
                            m.as_str(),
                            m.start(),
                            m.end()
                        );
                        spans.push(PiiSpan {
                            entity_type: $etype,
                            start: m.start(),
                            end: m.end(),
                            text: m.as_str().to_owned(),
                        });
                    }
                }
            };
        }

        // Priority order — each step skips ranges claimed by earlier passes.
        if self.emails {
            push_spans!(email_regex, EntityType::Email);
        }
        if self.credit_cards {
            push_spans!(credit_card_regex, EntityType::CreditCard, luhn_valid);
        }
        if self.ssns {
            push_spans!(ssn_regex, EntityType::Ssn, ssn_valid);
        }
        if self.phones {
            push_spans!(phone_regex, EntityType::Phone);
            push_spans!(international_phone_regex, EntityType::Phone);
        }
        if self.ip_addresses {
            push_spans!(ipv4_regex, EntityType::IpAddress);
        }
        if self.jwt_tokens {
            push_spans!(jwt_regex, EntityType::JwtToken);
        }
        if self.aws_keys {
            push_spans!(aws_key_regex, EntityType::AwsKey);
        }
        if self.env_secrets {
            // Use captures_iter so the span covers only the value (group 1),
            // preserving the key name (e.g. `API_KEY=`) in the output.
            for cap in env_secret_regex().captures_iter(text) {
                if let Some(val) = cap.get(1) {
                    if !overlaps_existing(&spans, val.start(), val.end()) {
                        debug!(
                            "NER[EnvSecret] {:?} {}..{}",
                            val.as_str(),
                            val.start(),
                            val.end()
                        );
                        spans.push(PiiSpan {
                            entity_type: EntityType::EnvSecret,
                            start: val.start(),
                            end: val.end(),
                            text: val.as_str().to_owned(),
                        });
                    }
                }
            }
        }

        // Custom rules (lower priority than built-ins)
        for rule in &self.custom_rules {
            for m in rule.pattern.find_iter(text) {
                if !overlaps_existing(&spans, m.start(), m.end()) {
                    let et = EntityType::Custom {
                        name: rule.name.clone(),
                        alias_prefix: rule.alias_prefix.clone(),
                    };
                    debug!(
                        "NER[{}] {:?} {}..{}",
                        rule.name,
                        m.as_str(),
                        m.start(),
                        m.end()
                    );
                    spans.push(PiiSpan {
                        entity_type: et,
                        start: m.start(),
                        end: m.end(),
                        text: m.as_str().to_owned(),
                    });
                }
            }
        }

        // Names last — most likely to false-positive inside other token types.
        // Uses a three-strategy approach: title signals, label/verb signals,
        // and a curated first/last name dictionary.  See `detect_names`.
        if self.names {
            spans.extend(detect_names(text, &spans));
        }

        spans.sort_unstable_by_key(|s| s.start);
        spans
    }
}

fn overlaps_existing(spans: &[PiiSpan], start: usize, end: usize) -> bool {
    spans.iter().any(|s| start < s.end && end > s.start)
}

// ── MockNer (test only) ───────────────────────────────────────────────────────

#[cfg(test)]
pub struct MockNer {
    pub entries: Vec<(EntityType, &'static str)>,
}

#[cfg(test)]
impl Ner for MockNer {
    fn find_spans(&self, text: &str) -> Vec<PiiSpan> {
        let mut spans = Vec::new();
        for (entity_type, token) in &self.entries {
            let mut search_from = 0usize;
            while let Some(pos) = text[search_from..].find(token) {
                let start = search_from + pos;
                let end = start + token.len();
                spans.push(PiiSpan {
                    entity_type: entity_type.clone(),
                    start,
                    end,
                    text: (*token).to_owned(),
                });
                search_from = end;
            }
        }
        spans.sort_unstable_by_key(|s| s.start);
        spans
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_email() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Contact support@airlock.rs for help");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, EntityType::Email);
    }

    #[test]
    fn detects_name() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Approved by Alice Johnson on March 14");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Name));
    }

    #[test]
    fn email_wins_over_name_overlap() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("john.smith@example.com");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, EntityType::Email);
    }

    #[test]
    fn spans_are_sorted_by_start_offset() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Alice Johnson emailed bob@corp.com last week");
        let starts: Vec<usize> = spans.iter().map(|s| s.start).collect();
        assert!(starts.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn detects_phone_us_dashes() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Call me at 555-867-5309 anytime");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Phone));
    }

    #[test]
    fn detects_ssn() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("SSN: 123-45-6789");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Ssn));
    }

    #[test]
    fn detects_credit_card_visa() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Card: 4111 1111 1111 1111");
        assert!(spans
            .iter()
            .any(|s| s.entity_type == EntityType::CreditCard));
    }

    #[test]
    fn detects_ipv4() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Connected from 192.168.0.1");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::IpAddress));
    }

    #[test]
    fn no_overlap_between_types() {
        let ner = RegexNer::default();
        // An email address must not also be detected as a name
        let spans = ner.find_spans("john.smith@example.com");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, EntityType::Email);
    }

    #[test]
    fn custom_rule_fires() {
        let rule = CompiledCustomRule {
            name: "EmployeeId".to_string(),
            alias_prefix: "Emp".to_string(),
            pattern: Regex::new(r"\bEMP-\d{5}\b").unwrap(),
        };
        let ner = RegexNer {
            custom_rules: vec![rule],
            ..RegexNer::default()
        };
        let spans = ner.find_spans("Employee EMP-00042 logged in");
        assert_eq!(spans.len(), 1);
        match &spans[0].entity_type {
            EntityType::Custom { name, .. } => assert_eq!(name, "EmployeeId"),
            _ => panic!("expected Custom entity type"),
        }
    }

    #[test]
    fn detects_credit_card_with_dashes() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Card: 4111-1111-1111-1111");
        assert!(spans
            .iter()
            .any(|s| s.entity_type == EntityType::CreditCard));
    }

    #[test]
    fn detects_mastercard() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Paid with 5111 1111 1111 1118");
        assert!(spans
            .iter()
            .any(|s| s.entity_type == EntityType::CreditCard));
    }

    #[test]
    fn detects_amex() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Amex: 3714 496353 98431");
        assert!(spans
            .iter()
            .any(|s| s.entity_type == EntityType::CreditCard));
    }

    #[test]
    fn detects_phone_with_parens() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Call (555) 867-5309 now");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Phone));
    }

    #[test]
    fn detects_phone_with_country_code() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Reach me at +1 555-867-5309");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Phone));
    }

    #[test]
    fn each_redact_toggle_suppresses_only_its_type() {
        let text =
            "Alice Johnson alice@corp.com 555-867-5309 123-45-6789 4111 1111 1111 1111 192.168.1.1";
        let types = [
            (
                EntityType::Name,
                RegexNer {
                    names: false,
                    ..RegexNer::default()
                },
            ),
            (
                EntityType::Email,
                RegexNer {
                    emails: false,
                    ..RegexNer::default()
                },
            ),
            (
                EntityType::Phone,
                RegexNer {
                    phones: false,
                    ..RegexNer::default()
                },
            ),
            (
                EntityType::Ssn,
                RegexNer {
                    ssns: false,
                    ..RegexNer::default()
                },
            ),
            (
                EntityType::CreditCard,
                RegexNer {
                    credit_cards: false,
                    ..RegexNer::default()
                },
            ),
            (
                EntityType::IpAddress,
                RegexNer {
                    ip_addresses: false,
                    ..RegexNer::default()
                },
            ),
        ];
        for (suppressed, ner) in &types {
            let spans = ner.find_spans(text);
            assert!(
                spans.iter().all(|s| &s.entity_type != suppressed),
                "{suppressed:?} should be suppressed but was detected"
            );
        }
    }

    #[test]
    fn redact_toggles_suppress_detection() {
        let ner = RegexNer {
            ip_addresses: false,
            emails: false,
            ..RegexNer::default()
        };
        // Neither email nor IP should be detected
        let spans = ner.find_spans("Alice Johnson logged in from 192.168.1.1 via alice@corp.com");
        assert!(spans.iter().all(|s| s.entity_type != EntityType::Email));
        assert!(spans.iter().all(|s| s.entity_type != EntityType::IpAddress));
        // Names should still be detected
        assert!(spans.iter().any(|s| s.entity_type == EntityType::Name));
    }

    #[test]
    fn luhn_rejects_invalid_card_number() {
        // 4111 1111 1111 1112 — last digit changed, Luhn fails
        assert!(!luhn_valid("4111111111111112"));
        assert!(!luhn_valid("1234567890123456"));
    }

    #[test]
    fn luhn_accepts_valid_card_numbers() {
        assert!(luhn_valid("4111111111111111")); // Visa test card
        assert!(luhn_valid("5500005555555559")); // Mastercard test card
        assert!(luhn_valid("371449635398431")); // Amex test card
    }

    #[test]
    fn invalid_card_shape_not_detected() {
        let ner = RegexNer::default();
        // Matches card pattern but fails Luhn
        let spans = ner.find_spans("4111 1111 1111 1112");
        assert!(spans
            .iter()
            .all(|s| s.entity_type != EntityType::CreditCard));
    }

    #[test]
    fn ssn_rejects_invalid_area_numbers() {
        assert!(!ssn_valid("000-12-3456")); // area 000
        assert!(!ssn_valid("666-12-3456")); // area 666
        assert!(!ssn_valid("900-12-3456")); // area 900+
        assert!(!ssn_valid("999-12-3456")); // area 999
    }

    #[test]
    fn ssn_accepts_valid_area_numbers() {
        assert!(ssn_valid("123-45-6789"));
        assert!(ssn_valid("001-01-0001")); // area 001 is valid
    }

    #[test]
    fn invalid_ssn_area_not_detected() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("SSN: 000-12-3456");
        assert!(spans.iter().all(|s| s.entity_type != EntityType::Ssn));
        let spans = ner.find_spans("SSN: 666-12-3456");
        assert!(spans.iter().all(|s| s.entity_type != EntityType::Ssn));
    }

    #[test]
    fn detects_international_phone_compact_e164() {
        let ner = RegexNer::default();
        assert!(ner
            .find_spans("Call +447911123456 now")
            .iter()
            .any(|s| s.entity_type == EntityType::Phone));
        assert!(ner
            .find_spans("Reach +14155551234 here")
            .iter()
            .any(|s| s.entity_type == EntityType::Phone));
    }

    #[test]
    fn detects_international_phone_formatted() {
        let ner = RegexNer::default();
        assert!(ner
            .find_spans("+44 7911 123456")
            .iter()
            .any(|s| s.entity_type == EntityType::Phone));
        assert!(ner
            .find_spans("+49 30 12345678")
            .iter()
            .any(|s| s.entity_type == EntityType::Phone));
    }

    #[test]
    fn detects_jwt_token() {
        let ner = RegexNer::default();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let spans = ner.find_spans(&format!("Authorization: Bearer {jwt}"));
        assert!(spans.iter().any(|s| s.entity_type == EntityType::JwtToken));
    }

    #[test]
    fn detects_aws_access_key() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Using key AKIAIOSFODNN7EXAMPLE for request");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::AwsKey));
    }

    #[test]
    fn detects_env_secret_equals() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("API_KEY=sk-abc123def456");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::EnvSecret));
    }

    #[test]
    fn detects_env_secret_colon() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("password: supersecretvalue");
        assert!(spans.iter().any(|s| s.entity_type == EntityType::EnvSecret));
    }

    #[test]
    fn env_secret_ignores_short_values() {
        let ner = RegexNer::default();
        // Value "abc" is only 3 chars — below the 6-char minimum
        let spans = ner.find_spans("password=abc");
        assert!(spans.iter().all(|s| s.entity_type != EntityType::EnvSecret));
    }

    #[test]
    fn mock_ner_finds_all_occurrences() {
        let ner = MockNer {
            entries: vec![(EntityType::Name, "Alice"), (EntityType::Email, "a@b.com")],
        };
        let spans = ner.find_spans("Alice wrote to a@b.com");
        assert_eq!(spans.len(), 2);
    }

    // ── Improved name detection tests ─────────────────────────────────────────

    // Strategy 1: title-triggered

    #[test]
    fn detects_single_surname_after_mr() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("The patient Mr. Smith was discharged");
        assert!(
            spans.iter().any(|s| s.entity_type == EntityType::Name && s.text == "Smith"),
            "single surname after Mr. should be detected"
        );
    }

    #[test]
    fn detects_full_name_after_dr() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Dr. Alice Johnson signed the report");
        assert!(
            spans
                .iter()
                .any(|s| s.entity_type == EntityType::Name && s.text == "Alice Johnson"),
            "full name after Dr. should be detected"
        );
    }

    #[test]
    fn detects_name_after_ms() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Please contact Ms. Rodriguez for details");
        assert!(
            spans
                .iter()
                .any(|s| s.entity_type == EntityType::Name && s.text == "Rodriguez"),
            "surname after Ms. should be detected"
        );
    }

    #[test]
    fn detects_name_after_prof() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Approved by Prof. David Chen");
        assert!(
            spans.iter().any(|s| s.entity_type == EntityType::Name),
            "name after Prof. should be detected"
        );
    }

    // Strategy 2a: label-triggered

    #[test]
    fn detects_name_from_name_label() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("name: Robert Brown");
        assert!(
            spans
                .iter()
                .any(|s| s.entity_type == EntityType::Name && s.text == "Robert Brown"),
            "full name after 'name:' label should be detected"
        );
    }

    #[test]
    fn detects_name_from_patient_label() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("patient: Sarah Connor");
        assert!(
            spans.iter().any(|s| s.entity_type == EntityType::Name),
            "name after 'patient:' label should be detected"
        );
    }

    #[test]
    fn detects_name_from_employee_label() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("employee: Carlos Rivera was onboarded");
        assert!(
            spans.iter().any(|s| s.entity_type == EntityType::Name),
            "name after 'employee:' label should be detected"
        );
    }

    #[test]
    fn detects_name_from_author_label() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("{\"author\": \"Jennifer Martinez\"}");
        assert!(
            spans.iter().any(|s| s.entity_type == EntityType::Name),
            "name after 'author:' label should be detected"
        );
    }

    // Strategy 2b: verb-context-triggered

    #[test]
    fn detects_name_after_named_verb() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("The account was created by a user named Emily Davis");
        assert!(
            spans.iter().any(|s| s.entity_type == EntityType::Name),
            "name after 'named' should be detected"
        );
    }

    #[test]
    fn detects_name_after_called_verb() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("The subscriber called Bob Williams cancelled");
        assert!(
            spans.iter().any(|s| s.entity_type == EntityType::Name),
            "name after 'called' should be detected"
        );
    }

    #[test]
    fn verb_context_does_not_fire_on_unknown_product_name() {
        // "called" followed by a word not in any name dictionary should not fire.
        let ner = RegexNer::default();
        let spans = ner.find_spans("the feature called Zephyr was launched");
        // "Zephyr" is not in first_names or last_names — should not be detected.
        assert!(
            spans.iter().all(|s| s.entity_type != EntityType::Name),
            "'called Zephyr' should not produce a name span"
        );
    }

    // Strategy 3: dictionary-based

    #[test]
    fn detects_high_confidence_first_plus_last() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Robert Brown approved the change at 09:00");
        assert!(
            spans
                .iter()
                .any(|s| s.entity_type == EntityType::Name && s.text == "Robert Brown"),
            "first+last dictionary match should be detected"
        );
    }

    #[test]
    fn detects_medium_confidence_first_name_only() {
        let ner = RegexNer::default();
        // "Jessica" is in first_names; "Nguyen" is in last_names — high confidence
        let spans = ner.find_spans("Jessica Nguyen submitted the ticket");
        assert!(
            spans.iter().any(|s| s.entity_type == EntityType::Name),
            "first+last dictionary match should be detected"
        );
    }

    #[test]
    fn detects_three_part_name() {
        let ner = RegexNer::default();
        // "Mary Jo Anderson" — first word in first_names, 3 words total
        let spans = ner.find_spans("Signed by Mary Jo Anderson");
        assert!(
            spans.iter().any(|s| s.entity_type == EntityType::Name),
            "three-part name should be detected"
        );
    }

    // False-positive prevention

    #[test]
    fn no_false_positive_new_york() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("The server is located in New York");
        // "New" is not in first_names
        assert!(
            spans.iter().all(|s| s.entity_type != EntityType::Name),
            "'New York' should not be detected as a name"
        );
    }

    #[test]
    fn no_false_positive_general_electric() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("General Electric reported strong earnings");
        // "General" is not in first_names
        assert!(
            spans.iter().all(|s| s.entity_type != EntityType::Name),
            "'General Electric' should not be detected as a name"
        );
    }

    #[test]
    fn no_false_positive_victoria_park() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Meet at Victoria Park at noon");
        // "Victoria" IS in first_names but "Park" is in is_non_person_word
        assert!(
            spans.iter().all(|s| s.entity_type != EntityType::Name),
            "'Victoria Park' should not be detected as a name"
        );
    }

    #[test]
    fn no_false_positive_national_bank() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Transferred funds to National Bank");
        // "National" is not in first_names
        assert!(
            spans.iter().all(|s| s.entity_type != EntityType::Name),
            "'National Bank' should not be detected as a name"
        );
    }

    #[test]
    fn no_false_positive_victoria_station() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Departing from Victoria Station");
        // "Station" is in is_non_person_word
        assert!(
            spans.iter().all(|s| s.entity_type != EntityType::Name),
            "'Victoria Station' should not be detected as a name"
        );
    }

    #[test]
    fn single_capitalized_word_not_detected_without_context() {
        let ner = RegexNer::default();
        // A lone surname with no title or label context — too ambiguous.
        let spans = ner.find_spans("Smith submitted the report");
        assert!(
            spans.iter().all(|s| s.entity_type != EntityType::Name),
            "single surname without context should not be detected"
        );
    }

    // Edge cases

    #[test]
    fn email_wins_over_name_in_address() {
        // Names strategy runs after email; overlapping spans are skipped.
        let ner = RegexNer::default();
        let spans = ner.find_spans("john.smith@example.com");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity_type, EntityType::Email);
    }

    #[test]
    fn name_and_email_both_detected_when_separate() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Alice Johnson sent alice@corp.com");
        assert!(
            spans.iter().any(|s| s.entity_type == EntityType::Name),
            "name should be detected separately from email"
        );
        assert!(
            spans.iter().any(|s| s.entity_type == EntityType::Email),
            "email should also be detected"
        );
    }

    #[test]
    fn names_toggle_disabled_suppresses_all_strategies() {
        let ner = RegexNer {
            names: false,
            ..RegexNer::default()
        };
        let text = "Dr. Alice Johnson — name: Robert Brown — named Emily Davis";
        let spans = ner.find_spans(text);
        assert!(
            spans.iter().all(|s| s.entity_type != EntityType::Name),
            "names toggle=false should suppress all strategies"
        );
    }

    #[test]
    fn title_dot_optional() {
        // "Mr Smith" (no period) should also fire.
        let ner = RegexNer::default();
        let spans = ner.find_spans("Mr Smith checked in");
        assert!(
            spans.iter().any(|s| s.entity_type == EntityType::Name && s.text == "Smith"),
            "title without period should still trigger detection"
        );
    }

    #[test]
    fn hyphenated_double_barrel_surname_after_title() {
        let ner = RegexNer::default();
        let spans = ner.find_spans("Dr. Mary-Jane Watson");
        // "Mary-Jane Watson" — title triggers detection regardless of hyphen
        assert!(
            spans.iter().any(|s| s.entity_type == EntityType::Name),
            "hyphenated name after title should be detected"
        );
    }
}
