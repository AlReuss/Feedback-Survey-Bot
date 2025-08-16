import os, time, hmac, hashlib, json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from apscheduler.schedulers.background import BackgroundScheduler
import pytz

# ---------- Config via env ----------
SLACK_BOT_TOKEN      = os.environ["SLACK_BOT_TOKEN"]           # xoxb-...
SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]
SURVEY_CHANNEL       = os.environ.get("SURVEY_CHANNEL", "#weekend-feedback-survey")
ADMIN_USER_ID        = os.environ.get("ADMIN_USER_ID")         # e.g., U07QE0R7TJA
TZ_NAME              = os.environ.get("TZ", "America/New_York")
TEST_TRIGGER_TOKEN   = os.environ.get("TEST_TRIGGER_TOKEN", "")

# Final prompts (8) — edit here anytime
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

SURVEY_DURATION = 24 * 60 * 60  # 24 hours (seconds)
tz = pytz.timezone(TZ_NAME)

app = Flask(__name__)
client = WebClient(token=SLACK_BOT_TOKEN)
scheduler = BackgroundScheduler(timezone=TZ_NAME)
scheduler.start()

# Runtime state for current survey
survey_open_until = None         # tz-aware datetime
survey_tag = None                # e.g., "2025-08-17"
latest_message_ts = None         # message to update/close
latest_message_channel = None    # channel id for that message

# ---------- Helpers ----------
def now_tz():
    return datetime.now(tz)

def verify_signature(req):
    timestamp = req.headers.get("X-Slack-Request-Timestamp", "")
    signature = req.headers.get("X-Slack-Signature", "")
    if not timestamp or not signature:
        return False
    # Protect against replay
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False
    basestring = f"v0:{timestamp}:{req.get_data(as_text=True)}"
    my_sig = "v0=" + hmac.new(SLACK_SIGNING_SECRET.encode(), basestring.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(my_sig, signature)

def survey_is_open():
    return survey_open_until is not None and now_tz() < survey_open_until

def format_csv_row(user_id, real_name, tag, answers):
    # Returns a single CSV row string; commas inside answers are replaced with semicolons
    sane = lambda s: (s or "").replace("\n", " ").replace("\r", " ").replace(",", ";").strip()
    fields = [tag, user_id, real_name] + [sane(answers.get(aid, "")) for aid, _ in QUESTIONS]
    header = ["tag", "user_id", "real_name"] + [f"q{i+1}" for i in range(len(QUESTIONS))]
    return header, ",".join(fields)

def dm_admin(user_id, answers, tag, late=False):
    # Resolve responder name
    try:
        info = client.users_info(user=user_id)
        real_name = info["user"].get("real_name") or info["user"]["profile"].get("real_name") or "Unknown"
    except SlackApiError:
        real_name = "Unknown"

    # Pretty summary
    lines = [f"*Weekly Survey Submission* (`{tag}`) from <@{user_id}> ({real_name})"]
    if late:
        lines.append("_Received after the survey window closed._")
    for i, (aid, label) in enumerate(QUESTIONS, start=1):
        val = (answers.get(aid, "") or "").strip() or "_(no answer)_"
        lines.append(f"\n*Q{i}.* {label}\n> {val}")
    pretty_text = "\n".join(lines)

    # CSV row (easy copy/paste)
    header, row = format_csv_row(user_id, real_name, tag, answers)
    csv_block = "```" + ",".join(header) + "\n" + row + "```"

    # Open IM with admin & send (requires im:write)
    try:
        im = client.conversations_open(users=ADMIN_USER_ID)
        dm_channel = im["channel"]["id"]
        client.chat_postMessage(channel=dm_channel, text=pretty_text)
        client.chat_postMessage(channel=dm_channel, text="CSV copy-paste:", blocks=[
            {"type":"section","text":{"type":"mrkdwn","text":"CSV copy-paste:"}},
            {"type":"section","text":{"type":"mrkdwn","text":csv_block}}
        ])
    except SlackApiError as e:
        print("dm_admin error:", e)

def post_survey():
    """Post survey message, open window 24h, schedule closing update."""
    global survey_open_until, survey_tag, latest_message_ts, latest_message_channel

    start = now_tz()
    survey_open_until = start + timedelta(seconds=SURVEY_DURATION)
    survey_tag = start.strftime("%Y-%m-%d")

    text = "📝 *Weekly Feedback Survey is now open!* (closes in 24 hours)"
    blocks = [
        {"type":"section","text":{"type":"mrkdwn","text":text}},
        {"type":"context","elements":[
            {"type":"mrkdwn","text":f"*Tag:* `{survey_tag}`  •  Closes: {survey_open_until.strftime('%a %I:%M %p %Z')}"}
        ]},
        {"type":"actions","elements":[
            {"type":"button","text":{"type":"plain_text","text":"Fill Out Survey"},
             "action_id":"open_modal","value":"open"}
        ]}
    ]
    try:
        res = client.chat_postMessage(channel=SURVEY_CHANNEL, text=text, blocks=blocks)
        latest_message_ts = res["ts"]
        latest_message_channel = res["channel"]  # this is the channel ID Slack used
    except SlackApiError as e:
        print("post_survey error:", e)
        return

    # Schedule auto-close message update
    try:
        # Remove existing close job if present
        try: scheduler.remove_job("close_current")
        except: pass
        scheduler.add_job(close_survey, "date", run_date=survey_open_until, id="close_current", replace_existing=True)
    except Exception as e:
        print("schedule close error:", e)

def close_survey():
    """Mark survey closed by updating the original message (disables button)."""
    global survey_open_until, survey_tag, latest_message_ts, latest_message_channel
    survey_open_until = None
    try:
        if latest_message_channel and latest_message_ts:
            closed_text = "✅ *Weekly Feedback Survey is now closed.*"
            closed_blocks = [
                {"type":"section","text":{"type":"mrkdwn","text":closed_text}},
                {"type":"context","elements":[{"type":"mrkdwn","text":f"*Tag:* `{survey_tag}`"}]}
            ]
            client.chat_update(channel=latest_message_channel, ts=latest_message_ts,
                               text=closed_text, blocks=closed_blocks)
    except SlackApiError as e:
        print("close_survey update error:", e)

# ---------- Slack interactivity ----------
def open_modal(trigger_id):
    # If window is closed, show a simple modal
    if not survey_is_open():
        view = {
            "type":"modal",
            "title":{"type":"plain_text","text":"Weekly Feedback"},
            "close":{"type":"plain_text","text":"Close"},
            "blocks":[{"type":"section","text":{"type":"mrkdwn","text":"⚠️ This survey window is closed. Please try again next week."}}]
        }
        try: client.views_open(trigger_id=trigger_id, view=view)
        except SlackApiError as e: print("open_modal (closed) error:", e)
        return

    blocks=[]
    for idx, (aid, label) in enumerate(QUESTIONS):
        blocks.append({
            "type":"input",
            "block_id":f"b{idx}",
            "label":{"type":"plain_text","text":label},
            "element":{"type":"plain_text_input","multiline":True,"action_id":aid}
        })
    view = {
        "type":"modal",
        "callback_id":"weekly_feedback_submit",
        "title":{"type":"plain_text","text":"Weekly Feedback"},
        "submit":{"type":"plain_text","text":"Submit"},
        "close":{"type":"plain_text","text":"Cancel"},
        "private_metadata": json.dumps({"survey_tag": survey_tag}),
        "blocks": blocks
    }
    try:
        client.views_open(trigger_id=trigger_id, view=view)
    except SlackApiError as e:
        print("open_modal error:", e)

@app.route("/slack/events", methods=["POST"])
def slack_events():
    if not verify_signature(request):
        return "bad signature", 403

    # Interactivity payloads
    if "payload" in request.form:
        payload = json.loads(request.form["payload"])
        ptype = payload.get("type")

        if ptype == "block_actions":
            trigger_id = payload.get("trigger_id")
            actions = payload.get("actions", [])
            if any(a.get("action_id") == "open_modal" for a in actions):
                open_modal(trigger_id)
            return "", 200

        if ptype == "view_submission" and payload.get("view", {}).get("callback_id") == "weekly_feedback_submit":
            user_id = payload.get("user", {}).get("id")
            state = payload.get("view", {}).get("state", {}).get("values", {})
            answers = {}
            # Extract answers by action_id
            for bid, inner in state.items():
                for aid, _ in QUESTIONS:
                    if aid in inner:
                        answers[aid] = inner[aid].get("value", "")
            meta = payload.get("view", {}).get("private_metadata", "{}")
            tag = json.loads(meta).get("survey_tag", "unknown")

            # If closed between open and submit, surface an error
            if not survey_is_open():
                # attach a generic error to the first block
                first_bid = next(iter(state.keys()))
                return jsonify({"response_action":"errors", "errors": {first_bid: "This survey has closed. Please try again next week."}}), 200

            dm_admin(user_id, answers, tag, late=False)
            return jsonify({"response_action":"clear"}), 200

        return "", 200

    # Slack URL verification (not used here)
    body = request.get_json(silent=True) or {}
    if body.get("type") == "url_verification":
        return jsonify({"challenge": body.get("challenge")})

    return "", 200

# ---------- Health & test ----------
@app.route("/health")
def health():
    return "ok", 200

@app.route("/trigger", methods=["GET", "POST"])
def trigger():
    token = request.args.get("token") or request.form.get("token")
    if TEST_TRIGGER_TOKEN and token != TEST_TRIGGER_TOKEN:
        return "unauthorized", 401
    post_survey()
    return "triggered", 200

# ---------- Scheduler ----------
def schedule_weekly():
    # Every Sunday at 12:00 PM in configured TZ
    try:
        # Replace existing if present
        try: scheduler.remove_job("weekly_post")
        except: pass
        scheduler.add_job(post_survey, "cron", day_of_week="sun", hour=12, minute=0,
                          id="weekly_post", replace_existing=True)
    except Exception as e:
        print("schedule_weekly error:", e)

if __name__ == "__main__":
    schedule_weekly()
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
