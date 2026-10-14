/** A check-only constraint: either side of a class contract must have no unmatched public keys. */
export type NoKeys<Keys extends never> = Keys;
