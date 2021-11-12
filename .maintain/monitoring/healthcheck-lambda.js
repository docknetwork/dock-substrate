const https = require('https');
const http = require('http');
const url = require('url');
const internal = require('stream');
const webhookUrl = process.env.SLACK_NOTIFCATION_WEBHOOK_URL;
const port = 9933;

async function statusIsValid(status) {
  return status.result && status.result.currentBlock && !isNaN(status.result.currentBlock);
}

async function sendSlackAlert(status, node) {
  const slackBlocks = {
    blocks: [
      {
        type: 'divider'
      },
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: `${node.network}`
        }
      }
    ],
    attachments: [{
      color: '#ff0000',
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*<http://${node.url}|${node.name}>* reported an error. (AWS Region: ${node.region})`
          }
        }
      ]
    },
    {
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `Healthcheck: _${process.env.AWS_LAMBDA_FUNCTION_NAME} (${process.env.AWS_REGION})_`
          }
        }
      ]
    }]
  };

  if (status.error) {
    if (status.error.code) {
      slackBlocks.attachments[0].blocks.push({
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Code:* ${status.error.code}`,
        }
      });
    }

    if (status.error.message) {
      slackBlocks.attachments[0].blocks.push({
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Message:* ${status.error.message}`,
        }
      });
    }
  }

  await httpPOST(webhookUrl, slackBlocks, https);
}

function httpPOST(urlStr, jsonData, protocol) {
  const promise = new Promise((resolve, reject) => {
    const data = JSON.stringify(jsonData);
    const uri = url.parse(urlStr);
    const options = {
      hostname: uri.hostname,
      port: uri.port,
      path: `${uri.pathname}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length
      },
      timeout: 3000
    };

    const req = protocol.request(options, res => {
      if (res.statusCode === 200) {
        res.on('data', d => {
          resolve(d.toString());
        });
      } else {
        reject(Error(`Unknown status: ${res.statusCode} ${urlStr}`));
      }
    });

    req.on('timeout', function () {
      req.abort();
      req.destroy();
      const msg = `Timeout after ${options.timeout} milliseconds. (uri: ${JSON.stringify(uri)})`;
      reject(new Error(msg, {
        message: msg,
        url: uri
      }));
    });

    req.on('error', error => {
      reject(new Error(error.message, error.options));
    });

    req.write(data);
    req.end();
  });
  return promise;
}

async function checkAPIStatus(node) {
  const blockNumberReq = {
    id: 1,
    jsonrpc: '2.0',
    method: 'system_syncState'
  };

  const status = await httpPOST(`http://${node.url}:${port}`, blockNumberReq, http)
    .then(async status => {
      console.log(`${node.network} - ${node.name} status: ${status}`);

      if (!statusIsValid(JSON.parse(status))) {
        sendSlackAlert(status, node);
      }

      return { status, node };
    })
    .catch(async err => {
      console.log(`Error caught: ${err}`);
      const errStatus = {
        error: {
          message: err.message
        }
      };

      sendSlackAlert(errStatus, node);

      return {
        status: errStatus,
        node
      };
    });

  return status;
}

exports.handler = async function (event) {
  const promises = [];
  const nodeUrls = JSON.parse(process.env.NODE_URLS);
  nodeUrls.forEach(node => {
    console.log(`checking ${node.network} - ${node.name}...`);
    promises.push(checkAPIStatus(node));
  });

  try {
    const results = await Promise.all(promises);
    console.log(results);
    return {
      statusCode: 200,
      body: JSON.stringify(results),
    };
  } catch (e) {
    console.error(e);
    await httpPOST(webhookUrl, {
      text: `Error during blockchain healthcheck: ${e.message}`,
    }, https);
    return {
      statusCode: 400,
      body: JSON.stringify({
        error: e.message
      }),
    };
  }
}
