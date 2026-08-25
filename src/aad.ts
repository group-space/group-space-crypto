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
