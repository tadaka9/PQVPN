# StrangeNet social feature matrix

This matrix compares durable interaction patterns rather than copying another
product's interface, branding, network model or engagement mechanics. Sources
are the vendors' own documentation: [Signal groups and mentions][signal],
[WhatsApp communities][whatsapp], [Discord messaging][discord],
[Telegram groups][telegram], [Slack actions and threads][slack], and
[Element/Matrix rooms][matrix].

| Social pattern | StrangeNet status | Privacy and architecture decision |
| --- | --- | --- |
| Rooms, nested topics and social spaces | Implemented | Validated room paths have up to eight levels. Pixel Commons maps its spaces to those canonical paths. |
| Direct messages | Implemented | A DM targets one authenticated 32-byte Peer ID; participant IP addresses are never rendered. |
| Replies / lightweight threads | Implemented | `reply_to` binds a reply to a message sequence without creating server-side history. |
| Emoji, reactions and stickers | Implemented | Bounded payloads use the authenticated session; arbitrary image and video uploads are not wire kinds. |
| Voice notes | Implemented | Bounded 16 kHz mono chunks are played live and are not written to chat history by PQVPN. |
| Delivery receipts | Implemented | Transport delivery is explicit. Read surveillance and attention tracking are not implemented. |
| Search | Implemented locally | Search covers only the visible in-memory transcript; there is no remote index. |
| Notification controls | Implemented locally | All activity, DMs/replies only, or mute. Notification bodies remain content-free. |
| Blocking | Implemented, session-only | A blocked authenticated Peer ID is rejected before the UI handler and excluded from direct, group and room fanout. Blocks are deliberately not uploaded to a service. |
| Group encryption | Implemented | Every message is independently encrypted for each authenticated member; there is no central group secret or recovery holder. |
| Presence | Bounded | The GUI shows only live authenticated sessions, not last-seen history or IP-derived location. |
| Persistent pins, bookmarks and cloud history | Not implemented | These need a user-controlled encrypted storage design; silently adding a local or central archive would contradict current session-only behavior. |
| Edit/delete for everyone | Not implemented | Reliable convergence across offline peers needs a signed replicated event model and explicit retention rules. A cosmetic local delete would be misleading. |
| Typing indicators and read state | Not implemented by default | They leak attention and behavior. Delivery receipts and optional priority notifications provide a lower-metadata alternative. |
| Polls, events and shared documents | Planned behind protocol design | They require deterministic merge rules, bounded state and abuse handling before becoming wire types. |
| Public searchable people directory | Rejected | Exact authenticated Peer IDs and out-of-band introductions avoid a scrapeable identity graph. |
| Algorithmic feed, streaks and engagement ranking | Rejected | StrangeNet is a user-chosen room, not an attention-optimization system. |
| Images, video and arbitrary files | Rejected for the current protocol | The present scope is text, bounded stickers and voice. Media would materially expand metadata, moderation and resource-exhaustion risk. |

The relevant baseline is therefore not “every checkbox”: it is the useful
conversation surface that can be implemented honestly over authenticated,
bounded, session-only P2P delivery. Features move from planned to implemented
only with wire-format tests, antiflood accounting, UI state evidence and clear
retention semantics.

[signal]: https://support.signal.org/hc/en-us/articles/360007319331-Group-chats
[whatsapp]: https://faq.whatsapp.com/495856382464992
[discord]: https://support.discord.com/hc/en-us/sections/115000458672-Messaging-and-Chat
[telegram]: https://telegram.org/faq
[slack]: https://slack.com/help/articles/360002063088-Understand-your-actions-in-Slack
[matrix]: https://docs.element.io/latest/element-support/matrix-rooms/understanding-matrix-rooms/
