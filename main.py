import os, time, hmac, hashlib, json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from apscheduler.schedulers.background import BackgroundScheduler
import pytz

# ---------- Config ----------
SLACK_BOT_TOKEN     = os.environ["SLACK_BOT_TOKEN"]          # xoxb-...
SLACK_SIGNING_SECRET= os.environ["SLACK_SIGNING_SECRET"]
SURVEY_CHANNEL      = os.environ.get("SURVEY_CHANNEL", "#test-feedback")  # channel name or ID
ADMIN_USER_ID       = os.environ.get("ADMIN_USER_ID")        # e.g., U07QE0R7TJA
TZ_NAME             = os.environ.get("TZ", "America/New_York")
TEST_TRIGGER_TOKEN  = os.environ.get("TEST_TRIGGER_TOKEN", "") # simple shared secret for /trigger

QUESTIONS = [
    ("q1", "What worked well this weekend? (assets, service flow, etc.) Why?"),
    ("q2", "What didn't work this weekend? (assets, service flow, etc.) Why?"),
    ("q3", "What would have been helpful to make this weekend even better for your site?"),
    ("q4", "Is there anything that needs to be IMMEDIATELY addressed to make your experience better for this next weekend?"),
]

SURVEY_SECONDS = 24 * 60 * 60  # 24 hours
tz = pytz.timezone(TZ_NAME)

# Runtime state for the current survey window
survey_open_until = None  # tz-aware datetime
survey_tag = None         # e.g., "2025-08-17"

app = Flask(__name__)
client = WebClient(token=SLACK_BOT_TOKEN)

# ---------- Helpers ----------
def now_tz():
    return datetime.now(tz)

def sign_ok(req):
    ts = req.headers.get("X-Slack-Request-Timestamp", "")
    sig = req.headers.get("X-Slack-Signature", "")
    if not ts or not sig: return False
    if abs(time.time() - int(ts)) > 60 * 5:
        return False
    basestring = f"v0:{ts}:{req.get_data(as_text=True)}"
    mysig = "v0=" + hmac.new(SLACK_SIGNING_SECRET.encode(), basestring.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mysig, sig)

def survey_is_open():
    return survey_open_until and now_tz() < survey_open_until

def post_survey():
    global survey_open_until, survey_tag
    start = now_tz()
    survey_open_until = start + timedelta(seconds=SURVEY_SECONDS)
    survey_tag = start.strftime("%Y-%m-%d")  # ties responses to that Sunday

    text = "📝 *Weekly Feedback Survey is now open!* (closes in 24 hours)"
    blocks = [
        {"type":"section","text":{"type":"mrkdwn","text":text}},
        {"type":"context","elements":[{"type":"mrkdwn","text":f"*Tag:* `{survey_tag}`  •  Closes: {survey_open_until.strftime('%a %I:%M %p %Z')}"}]},
        {"type":"actions","elements":[
            {"type":"button","text":{"type":"plain_text","text":"Fill Out Survey"},
             "action_id":"open_modal","value":"open"}
        ]}
    ]
    try:
        client.chat_postMessage(channel=SURVEY_CHANNEL, text=text, blocks=blocks)
    except SlackApiError as e:
        print("post_survey error:", e)

def open_modal(trigger_id):
    if not survey_is_open():
        # Show a quick modal stating survey closed
        closed = {
            "type":"modal",
            "title":{"type":"plain_text","text":"Weekly Feedback"},
            "close":{"type":"plain_text","text":"Close"},
            "blocks":[{"type":"section","text":{"type":"mrkdwn","text":"⚠️ This survey window is closed. Please try again next week."}}]
        }
        client.views_open(trigger_id=trigger_id, view=closed)
        return

    blocks=[]
    for idx,(aid,label) in enumerate(QUESTIONS):
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
    client.views_open(trigger_id=trigger_id, view=view)

def dm_admin(user_id, answers, tag):
    # Resolve real name (optional)
    try:
        info = client.users_info(user=user_id)
        real_name = info["user"].get("real_name") or info["user"].get("profile",{}).get("real_name") or "Unknown"
    except SlackApiError:
        real_name = "Unknown"

    lines = [f"*Weekly Survey Submission* (`{tag}`) from <@{user_id}> ({real_name})"]
    for i,(aid,label) in enumerate(QUESTIONS, start=1):
        val = answers.get(aid,"").strip() or "_(no answer)_"
        lines.append(f"\n*Q{i}.* {label}\n> {val}")
    msg = "\n".join(lines)

    # Send as DM to admin (ADMIN_USER_ID must be a user ID like U07QE0R7TJA)
    client.chat_postMessage(channel=ADMIN_USER_ID, text=msg)

# ---------- Web endpoints ----------
@app.route("/health")
def health(): return "ok", 200

@app.route("/trigger", methods=["POST","GET"])
def trigger():
    # Manual trigger for testing. Protect with TEST_TRIGGER_TOKEN.
    token = request.args.get("token") or request.form.get("token")
    if TEST_TRIGGER_TOKEN and token != TEST_TRIGGER_TOKEN:
        return "unauthorized", 401
    post_survey()
    return "triggered", 200

@app.route("/slack/events", methods=["POST"])
def slack_events():
    if not sign_ok(request): return "bad signature", 403

    # Interactivity payloads come as form-encoded "payload"
    if "payload" in request.form:
        payload = json.loads(request.form["payload"])
        ptype = payload.get("type")

        if ptype == "block_actions":
            trigger_id = payload.get("trigger_id")
            # Any button with action_id "open_modal" opens the form
            actions = payload.get("actions", [])
            if any(a.get("action_id")=="open_modal" for a in actions):
                open_modal(trigger_id)
            return "", 200

        if ptype == "view_submission" and payload.get("view",{}).get("callback_id")=="weekly_feedback_submit":
            user_id = payload.get("user",{}).get("id")
            state = payload.get("view",{}).get("state",{}).get("values",{})
            answers={}
            for bid, inner in state.items():
                # inner like {"q1":{"type":"plain_text_input","value": "..."}}
                for aid,_ in QUESTIONS:
                    if aid in inner:
                        answers[aid] = inner[aid].get("value","")
            # read tag back
            meta = payload.get("view",{}).get("private_metadata","{}")
            tag = json.loads(meta).get("survey_tag","unknown")
            dm_admin(user_id, answers, tag)
            return jsonify({"response_action":"clear"}), 200

        return "", 200

    # URL verification (Events API) not used here
    body = request.get_json(silent=True) or {}
    if body.get("type") == "url_verification":
        return jsonify({"challenge": body.get("challenge")})

    return "", 200

# ---------- Scheduler ----------
def schedule_jobs():
    # Post every Sunday at 12:00 PM in configured TZ
    sched = BackgroundScheduler(timezone=TZ_NAME)
    sched.add_job(post_survey, "cron", day_of_week="sun", hour=12, minute=0, id="weekly_post", replace_existing=True)
    sched.start()

if __name__ == "__main__":
    schedule_jobs()
    # Render provides PORT env on deploy
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
