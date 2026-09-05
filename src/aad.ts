/**
 * Shared AAD (context-binding) labels for encrypted fields. These are part of
 * the ciphertext contract (the value used to encrypt must exactly match the one
 * used to decrypt), so they live in one place. In particular, rich push includes
 * the AAD in its payload and the service worker decrypts with it, so a drift
 * between the client's encrypt call and the server's push payload would silently
 * fall back to a generic notification.
 */
export const DISCUSSION_TITLE_AAD = "discussion.thread.title";
export const DISCUSSION_POST_BODY_AAD = "discussion.post.body";

// Photo albums (issue #110): the album name + description are sealed under the
// Group Key; the server never sees them. Legacy plaintext rows fall back until a
// client-side backfill re-encrypts them.
export const ALBUM_TITLE_AAD = "album.title";
export const ALBUM_DESCRIPTION_AAD = "album.description";

// Events + RSVPs (issue #87). Title/description/location and the RSVP answer
// ({status, guests}) are encrypted under the Group Key; these labels bind each
// ciphertext to its field.
export const EVENT_TITLE_AAD = "event.title";
export const EVENT_DESCRIPTION_AAD = "event.description";
export const EVENT_LOCATION_AAD = "event.location";
export const RSVP_ANSWER_AAD = "event.rsvp.answer";
// Times are encrypted too (issue #87): each is an ISO-8601 string sealed under
// the Group Key, decrypted client-side for sorting/splitting/display.
export const EVENT_START_AAD = "event.startsAt";
export const EVENT_END_AAD = "event.endsAt";
export const EVENT_RSVPBY_AAD = "event.rsvpBy";
export const EVENT_CAPACITY_AAD = "event.capacity";

// The sender's display name inside a push payload (#557). Sealed CLIENT-side by
// the composer of the post, because the server holds no group key and the
// member's name must not ride beside the ciphertext in the clear: a lock screen
// reading "Alice Chen started a discussion" reveals who is talking to whom,
// which is the social graph, the thing the payload was already careful not to
// leak about the content. Its own AAD, so a sealed name can never be replayed
// where a body or title is expected, nor the reverse.
export const PUSH_SENDER_AAD = "push.sender";

// Chip In, the group payment helper (issue #111). Every detail (title, amount, and
// the collector's payment label/link) is sealed under the Group Key; the server
// can't read it, so the create notification is generic and details render
// in-app. These labels bind each ciphertext to its field.
export const CHIPIN_TITLE_AAD = "chipin.title";
export const CHIPIN_DESCRIPTION_AAD = "chipin.description";
export const CHIPIN_AMOUNT_AAD = "chipin.amount";
export const CHIPIN_AMOUNT_UNIT_AAD = "chipin.amountUnit";
export const CHIPIN_PAYMENT_LABEL_AAD = "chipin.paymentLabel";
export const CHIPIN_PAYMENT_URL_AAD = "chipin.paymentUrl";
// A Chip In's payment options as a JSON array of {method, handle} (issue #111).
export const CHIPIN_PAYMENTS_AAD = "chipin.payments";
// A member's saved payment methods on their profile (same JSON shape), used to
// pre-fill their Chip Ins.
export const MEMBER_PAYMENTS_AAD = "member.payments";

// Directory contact fields (profile forms encrypt, the directory view and
// vCard export decrypt). Three files hand-typed these before they lived here.
export const DIRECTORY_PHONE_AAD = "directory.phone";
export const DIRECTORY_ADDRESS_AAD = "directory.address";
export const DIRECTORY_CHILD_NAME_AAD = "directory.child.name";
export const DIRECTORY_CHILD_GRADE_AAD = "directory.child.grade";

// The media container's length manifest. Every frame binds its own index, so
// frames cannot be reordered or moved between files, and the Poly1305 tag
// catches truncation INSIDE a frame. Nothing bound the number of frames, so
// whole frames removed from the end produced a shorter file that opened
// without error. Sealing the frame count and plaintext length under the file
// key gives a reader something to check the container against that the party
// storing it cannot forge. Composed with the container's context label, so a
// "full" manifest can never stand in for a "thumb".
export const MEDIA_MANIFEST_AAD = "media.manifest";

// The purpose tag on a passphrase-wrapped secret. A WrappedSecret seals with no
// context of its own, so two blobs wrapped under one passphrase, several
// membership private keys under a single account password for instance, are
// interchangeable: swapping them hands the holder the wrong key in the right
// slot. Because keys are random the visible result is a failure further down
// rather than a disclosure, which makes it a robustness problem, and a
// confusing one to diagnose.
//
// Composed with a caller-chosen purpose, so the caller supplies the identity
// (a membership id, a role) and never has to know this prefix. Passing no
// purpose keeps the original null-AAD behaviour exactly, which is what lets
// every blob wrapped before this existed keep opening.
export const WRAPPED_SECRET_AAD = "wrap.secret";

// Group identity, sealed for the Zero product (app issue #656; boundary audit
// section 1). In Zero the group's own name, tagline and description are sealed
// under the Group Key and rendered by decrypt islands; the server holds only
// ciphertext and an opaque id. The parent-market product keeps these plaintext
// (its join screen renders them before a viewer holds any key), so presence of
// these labels says nothing about which mode an instance runs.
export const GROUP_NAME_AAD = "group.name";
export const GROUP_TAGLINE_AAD = "group.tagline";
export const GROUP_DESCRIPTION_AAD = "group.description";

// A member's display name, sealed under the Group Key (app issue #694;
// boundary audit section 2). Distinct from PUSH_SENDER_AAD above on purpose:
// that label binds a name composed INTO a push payload, this one binds the
// member row's own stored name, and the two must never be replayable into
// each other's slots.
export const MEMBER_DISPLAY_NAME_AAD = "member.displayName";

// The encrypted group file library (app issue #647). A file's name IS content,
// so it is sealed like any field; the metadata blob seals {mime, note?} as one
// JSON value so type and note cannot be mixed across files.
export const FILE_NAME_AAD = "file.name";
export const FILE_META_AAD = "file.meta";
