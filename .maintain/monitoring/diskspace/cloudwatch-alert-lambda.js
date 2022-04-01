// borrowed and modified from https://raw.githubusercontent.com/assertible/lambda-cloudwatch-slack/master/index.js
var AWS = require('aws-sdk');
var url = require('url');
var https = require('https');
const hookUrl = process.env.SLACK_NOTIFCATION_WEBHOOK_URL;
const environment = process.env.BLOCKCHAIN_ENVIRONMENT;

var postMessage = function (message, callback) {
  var body = JSON.stringify(message);
  var options = url.parse(hookUrl);
  options.method = 'POST';
  options.headers = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  };

  var postReq = https.request(options, function (res) {
    var chunks = [];
    res.setEncoding('utf8');
    res.on('data', function (chunk) {
      return chunks.push(chunk);
    });
    res.on('end', function () {
      var body = chunks.join('');
      if (callback) {
        callback({
          body: body,
          statusCode: res.statusCode,
          statusMessage: res.statusMessage
        });
      }
    });
    return res;
  });

  postReq.write(body);
  postReq.end();
};

var handleCloudWatch = function (event, context) {
  var timestamp = (new Date(event.Records[0].Sns.Timestamp)).getTime() / 1000;
  var message = JSON.parse(event.Records[0].Sns.Message);
  var region = event.Records[0].EventSubscriptionArn.split(":")[3];
  var account = event.Records[0].EventSubscriptionArn.split(":")[4];
  var subject = "AWS CloudWatch Notification";
  var alarmName = message.AlarmName;
  var metricName = message.Trigger.MetricName;
  var oldState = message.OldStateValue;
  var newState = message.NewStateValue;
  var alarmDescription = message.AlarmDescription;
  var alarmReason = message.NewStateReason;
  var trigger = message.Trigger;
  var color = "warning";

  if (message.NewStateValue === "ALARM") {
    color = "danger";
  } else if (message.NewStateValue === "OK") {
    color = "good";
  }

  var slackMessage = {
    text: `*${environment} (${subject})*`,
    attachments: [
      {
        "color": color,
        "fields": [
          { "title": "Alarm Name", "value": alarmName, "short": true },
          { "title": "Alarm Description", "value": alarmDescription, "short": false },
          {
            "title": "Trigger",
            "value": trigger.Statistic + " "
              + metricName + " "
              + trigger.ComparisonOperator + " "
              + trigger.Threshold + " for "
              + trigger.EvaluationPeriods + " period(s) of "
              + trigger.Period + " seconds.",
            "short": false
          },
          { "title": "Old State", "value": oldState, "short": true },
          { "title": "Current State", "value": newState, "short": true },
          { "title": "Alarm Reason", "value": alarmReason, "short": false },
          {
            "title": "Link to Alarm",
            "value": "https://console.aws.amazon.com/cloudwatch/home?region=" + region + "#alarm:alarmFilter=ANY;name=" + encodeURIComponent(alarmName),
            "short": false
          },
        ],
        "ts": timestamp
      }
    ]
  };
  const dimensionsAttachment = {
    fields: [
      {
        "title": "region",
        "value": region,
        "short": true
      },
      {
        "title": "account",
        "value": account,
        "short": true
      },
    ],
  };
  trigger.Dimensions.sort().map(d => {
    dimensionsAttachment.fields.push({
      "title": d.name,
      "value": d.value,
      "short": true
    });
  });
  slackMessage.attachments.unshift(dimensionsAttachment);
  return slackMessage;
};

var handleCatchAll = function (event, context) {

  var record = event.Records[0];
  var subject = record.Sns.Subject;
  var timestamp = new Date(record.Sns.Timestamp).getTime() / 1000;
  var message = JSON.parse(record.Sns.Message);
  var color = "warning";

  if (message.NewStateValue === "ALARM") {
    color = "danger";
  } else if (message.NewStateValue === "OK") {
    color = "good";
  }

  // Add all of the values from the event message to the Slack message description
  var description = "";
  for (const key in message) {

    var renderedMessage = typeof message[key] === 'object'
      ? JSON.stringify(message[key])
      : message[key];

    description = description + "\n" + key + ": " + renderedMessage;
  }

  var slackMessage = {
    text: "*" + subject + "*",
    attachments: [
      {
        "color": color,
        "fields": [
          { "title": "Message", "value": record.Sns.Subject, "short": false },
          { "title": "Description", "value": description, "short": false }
        ],
        "ts": timestamp
      }
    ]
  };

  return slackMessage;
};

var processEvent = function (event, context) {
  console.log("sns received:" + JSON.stringify(event, null, 2));
  var slackMessage = null;
  var eventSubscriptionArn = event.Records[0].EventSubscriptionArn;
  var eventSnsSubject = event.Records[0].Sns.Subject || 'no subject';
  var eventSnsMessageRaw = event.Records[0].Sns.Message;
  var eventSnsMessage = null;

  try {
    eventSnsMessage = JSON.parse(eventSnsMessageRaw);
  }
  catch (e) {
    console.error(e)
  }

  if (eventSnsMessage && 'AlarmName' in eventSnsMessage && 'AlarmDescription' in eventSnsMessage) {
    console.log("processing cloudwatch notification");
    slackMessage = handleCloudWatch(event, context);
  }
  else {
    slackMessage = handleCatchAll(event, context);
  }

  postMessage(slackMessage, function (response) {
    if (response.statusCode < 400) {
      console.info('message posted successfully');
      context.succeed();
    } else if (response.statusCode < 500) {
      console.error("error posting message to slack API: " + response.statusCode + " - " + response.statusMessage);
      // Don't retry because the error is due to a problem with the request
      context.succeed();
    } else {
      // Let Lambda retry
      context.fail("server error when processing message: " + response.statusCode + " - " + response.statusMessage);
    }
  });
};

exports.handler = function (event, context) {
  if (hookUrl) {
    processEvent(event, context);
  } else {
    context.fail('hook url has not been set.');
  }
};
