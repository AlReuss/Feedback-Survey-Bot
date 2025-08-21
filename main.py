import os, time, hmac, hashlib, json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import pytz

# ---------- Env ----------
SLACK_BOT_TOKEN      = os.environ["SLACK_BOT_TOKEN"]           # xoxb-...
SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]
SURVEY_CHANNEL       = os.environ.get("SURVEY_CHANNEL", "#weekend-feedback-survey")
ADMIN_USER_ID        = os.environ.get("ADMIN_USER_ID")         # e.g., U07QE0R7TJA
TZ_NAME              = os.environ.get("TZ", "America/New_York")
TEST_TRIGGER_TOKEN   = os.environ.get("TEST_TRIGGER_TOKEN", "")
# Optional: shorten window for testing; default is 24h
SURVEY_DURATION_SECONDS = int(os.environ.get("SURVEY_DURATION_SECONDS", str(24*60*60)))

tz = pytz.timezone(TZ_NAME)
app = Flask(__name__)
client = WebClient(token=SLACK_BOT_TOKEN)

# Final prompts (edit here any time)
QUESTIONS = [
    ("q1", "What worked well this weekend? (Graphics, Song Supports, Service Flow, Communication of Vision, etc.) Why?"),
    ("q2", "What didn't work well this weekend? (Graphics, Song Supports, Service Flow, Communication of Vision, etc.) Why?"),
    ("q3", "Did the service make sense from beginning to end? Did each component piece seem to fit well together, or did it feel disjointed in some way? Why?"),
    ("q4", "What was this weekend's \"Big Win\" for your site? Why?"),
    ("q5", "What was this weekend's \"Big Miss\" for your site? Why?"),
    ("q6", "Is there anything that needs to be IMMEDIATELY addressed to make the experience at your site better for next weekend?"),
    ("q7", "What feedback would be most helpful for Oakley and Creative Teams to hear from your site?"),
    ("q8", "Please provide any additional feedback here. (Be specific!)"),
]

def now_tz() -> datetime:
    return datetime.now(tz)

# ----- Slack signature verify -----
def verify_sig(req) -> bool:
    ts = req.headers.get("X-Slack-Request-Timestamp", "")
    sig = req.headers.get("X-Slack-Signature", "")
    if not ts or not sig:
        return False
    if abs(time.time() - int(ts)) > 60*5:  # replay guard
        return False
    basestring = f"v0:{ts}:{req.get_data(as_text=True)}"
    my_sig = "v0=" + hmac.new(SLACK_SIGNING_SECRET.encode(), basestring.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(my_sig, sig)

# ----- DM formatting -----
def format_csv_row(user_id, real_name, tag, answers):
    def sane(s): return (s or "").replace("\n"," ").replace("\r"," ").replace(",",";").strip()
    header = ["tag","user_id","real_name"] + [f"q{i+1}" for i in range(len(QUESTIONS))]
    fields = [tag, user_id, real_name] + [sane(answers.get(aid, "")) for aid,_ in QUESTIONS]
    return ",".join(header), ",".join(fields)

def dm_admin(user_id, answers, tag, late=False):
    # Lookup responder name
    try:
        info = client.users_info(user=user_id)
        real_name = info["user"].get("real_name") or info["user"]["profile"].get("real_name") or "Unknown"
    except SlackApiError:
        real_name = "Unknown"

    # Pretty block
    lines = [f"*Weekly Survey Submission* (`{tag}`) from <@{user_id}> ({real_name})"]
    if late:
        lines.append("_Received after the survey window closed._")
    for i,(aid,label) in enumerate(QUESTIONS, start=1):
        v = (answers.get(aid,"") or "").strip() or "_(no answer)_"
        lines.append(f"\n*Q{i}.* {label}\n> {v}")
    pretty = "\n".join(lines)

    # CSV block (easy copy/paste)
    header, row = format_csv_row(user_id, real_name, tag, answers)
    csv_block = "```" + header + "\n" + row + "```"

    try:
        # Requires im:write scope
        im = client.conversations_open(users=ADMIN_USER_ID)
        dm_ch = im["channel"]["id"]
        client.chat_postMessage(channel=dm_ch, text=pretty)
        client.chat_postMessage(channel=dm_ch, text="CSV copy-paste:", blocks=[
            {"type":"section","text":{"type":"mrkdwn","text":"CSV copy-paste:"}},
            {"type":"section","text":{"type":"mrkdwn","text":csv_block}}
        ])
    except SlackApiError as e:
        print("dm_admin error:", e)

# ----- Posting & modal (stateless window) -----
def post_survey():
    start = now_tz()
    close_at = start + timedelta(seconds=SURVEY_DURATION_SECONDS)
    tag = start.strftime("%Y-%m-%d")

    # Encode the close time into the button; survives restarts
    button_value = json.dumps({"tag": tag, "close_at": close_at.isoformat()})

    text = "📝 *Weekly Feedback Survey is now open!* (closes in 24 hours)"
    blocks = [
        {"type":"section","text":{"type":"mrkdwn","text":text}},
        {"type":"context","elements":[
            {"type":"mrkdwn","text":f"*Tag:* `{tag}`  •  Closes: {close_at.strftime('%a %I:%M %p %Z')}"}
        ]},
        {"type":"actions","elements":[
            {"type":"button","text":{"type":"plain_text","text":"Fill Out Survey"},
             "action_id":"open_modal","value":button_value}
        ]}
    ]
    try:
        client.chat_postMessage(channel=SURVEY_CHANNEL, text=text, blocks=blocks)
    except SlackApiError as e:
        print("post_survey error:", e)

def open_modal(trigger_id, button_value):
    try:
        data = json.loads(button_value or "{}")
    except Exception:
        data = {}
    tag = data.get("tag")
    close_at_iso = data.get("close_at")

    # Parse close_at and enforce window
    try:
        close_at = datetime.fromisoformat(close_at_iso)
        if close_at.tzinfo is None:
            close_at = tz.localize(close_at)
    except Exception:
        close_at = now_tz() - timedelta(seconds=1)  # force closed

    if now_tz() > close_at:
        view = {
            "type":"modal",
            "title":{"type":"plain_text","text":"Weekly Feedback"},
            "close":{"type":"plain_text","text":"Close"},
            "blocks":[{"type":"section","text":{"type":"mrkdwn","text":"⚠️ This survey window is closed. Please try again next week."}}]
        }
        try: client.views_open(trigger_id=trigger_id, view=view)
        except SlackApiError as e: print("open_modal (closed) error:", e)
        return

    # Build modal
    blocks=[]
    for idx,(aid,label) in enumerate(QUESTIONS):
        blocks.append({
            "type":"input","block_id":f"b{idx}",
            "label":{"type":"plain_text","text":label},
            "element":{"type":"plain_text_input","multiline":True,"action_id":aid}
        })
    view = {
        "type":"modal",
        "callback_id":"weekly_feedback_submit",
        "title":{"type":"plain_text","text":"Weekly Feedback"},
        "submit":{"type":"plain_text","text":"Submit"},
        "close":{"type":"plain_text","text":"Cancel"},
        "private_metadata": json.dumps({"tag": tag, "close_at": close_at_iso}),
        "blocks": blocks
    }
    try:
        client.views_open(trigger_id=trigger_id, view=view)
    except SlackApiError as e:
        print("open_modal error:", e)

# ----- Routes -----
@app.route("/health")
def health(): return "ok", 200

@app.route("/trigger", methods=["GET","POST"])
def trigger():
    token = request.args.get("token") or request.form.get("token")
    if TEST_TRIGGER_TOKEN and token != TEST_TRIGGER_TOKEN:
        return "unauthorized", 401
    post_survey()
    return "triggered", 200

@app.route("/slack/events", methods=["POST"])
def slack_events():
    if not verify_sig(request): return "bad signature", 403

    if "payload" in request.form:
        payload = json.loads(request.form["payload"])
        ptype = payload.get("type")

        if ptype == "block_actions":
            trigger_id = payload.get("trigger_id")
            for a in payload.get("actions", []):
                if a.get("action_id") == "open_modal":
                    open_modal(trigger_id, a.get("value"))
                    break
            return "", 200

        if ptype == "view_submission" and payload.get("view",{}).get("callback_id") == "weekly_feedback_submit":
            user_id = payload.get("user",{}).get("id")
            state = payload.get("view",{}).get("state",{}).get("values",{})
            meta = json.loads(payload.get("view",{}).get("private_metadata","{}"))
            tag = meta.get("tag","unknown")
            close_at_iso = meta.get("close_at")

            try:
                close_at = datetime.fromisoformat(close_at_iso)
                if close_at.tzinfo is None:
                    close_at = tz.localize(close_at)
            except Exception:
                close_at = now_tz() - timedelta(seconds=1)

            if now_tz() > close_at:
                # Show inline error on first field
                first_bid = next(iter(state.keys()))
                return jsonify({"response_action":"errors","errors":{first_bid:"This survey has closed. Please try again next week."}}), 200

            # Collect answers
            answers = {}
            for bid, inner in state.items():
                for aid,_ in QUESTIONS:
                    if aid in inner:
                        answers[aid] = inner[aid].get("value","")
            dm_admin(user_id, answers, tag, late=False)
            return jsonify({"response_action":"clear"}), 200

        return "", 200

    # URL verification fallback
    body = request.get_json(silent=True) or {}
    if body.get("type") == "url_verification":
        return jsonify({"challenge": body.get("challenge")})
    return "", 200

@app.route("/")
def home():
    return "Feedback Survey Bot is running. Try /health or /trigger?token=...", 200
