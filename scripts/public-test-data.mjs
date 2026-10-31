// The public test data of the comparison of the command-line tool with the package. Only public
// data: BIP39's all-zero phrases and containers of them under the public test password. The browser
// checks hold a deliberate copy in xtask/pages/page-data.js: a change goes to both.

/** BIP39's all-zero 12-word phrase. */
export const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/** BIP39's all-zero 24-word phrase. */
export const ZERO_24 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
/** The container of PHRASE, of its own length, at the reduced cost of the tests (suite 4). */
export const REDUCED_COST_SAME_LENGTH_CONTAINER =
  "program adjust rain raven flip eternal spider bulb under soup enrich ensure";
/**
 * The same phrase and password at full size: the public vector zero-12, whose repair words an
 * independent implementation computed.
 */
export const FULL_SIZE_CONTAINER =
  "donate stove tower picnic iron rescue trick shrimp roof rib home cigar bag pledge also nerve cycle famous provide heart ahead chunk caution peace";
/** Packs to the first state of AMBIGUOUS_STATES in src/packing.rs, which also passes the 21-word check. */
export const AMBIGUOUS_12_WORDS =
  "essence drama mule dolphin bitter rain abandon abandon able human mule relax";
