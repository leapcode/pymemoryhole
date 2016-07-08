from email.parser import Parser


FROM = "me@domain.com"
TO = "you@other.com"
SUBJECT = "some subject"
BODY = "body text"
MESSAGE_ID = "m@message.id"
IN_REPLY_TO = "reply@message.id"
USER_AGENT = "bitmask MUA"
EMAIL = """From: %(from)s
To: %(to)s
Message-ID: %(message-id)s
In-Reply-To: %(in-reply-to)s
User-Agent: %(user-agent)s
Subject: %(subject)s

%(body)s
""" % {
    "from": FROM,
    "to": TO,
    "message-id": MESSAGE_ID,
    "in-reply-to": IN_REPLY_TO,
    "user-agent": USER_AGENT,
    "subject": SUBJECT,
    "body": BODY
}

parser = Parser()
dummy_msg = parser.parsestr(EMAIL)


def get_body(data):
    return parser.parsestr(data).get_payload()
