"""Notifications: messages when a remediation needs a person or finishes (docs/design/notifications.md).

`outbox.record` writes them in the transaction of the status change they report; `delivery`
sends them from the `notify` queue.
"""
