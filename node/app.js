'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'), 
  http = require("http"),
  request = require('request'), 
  FB = require("fb"),
  ccap = require('ccap');

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});

app.post('/webhook', function (req, res) {
  var data = req.body;

  if (data.object == 'page') {
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    res.sendStatus(200);
  }
});

app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query['account_linking_token'];
  var redirectURI = req.query['redirect_uri'];

  var authCode = "1234567890";

  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

app.get('/img/:par', function(req, res) {
    
  var captcha = ccap({ generate:function(){ return req.params.par; } });
  var arr = captcha.get();
  res.write(arr[1]);
  res.end();
});

function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam, 
    timeOfAuth);
    
  sendTextMessage(senderID, "Authentication successful");
}
 
  //查詢是否開始
  var start = {};
  //查詢到第幾個步驟
  var step = {};
  //紀錄查詢筆數
  var query_count = {};
  
  //儲存搜尋項目
  var search = {};
  var req = [];
  var text = {};
  
  const pattern = {
    "": "無",
    "N": "未輸入",
    "M": "公",
    "F": "母",
    "MINI": "迷你",
    "SMALL": "小型",
    "MEDIUM": "中型",
    "BIG": "大型",
    "NONE": "未公告",
    "OPEN": "開放認養",
    "ADOPTED": "已認養",
    "OTHER": "其他",
    "DEAD": "死亡",
    "CHILD": "幼年",
    "ADULT": "成年"
    };
  const _pattern = {
    "N": "未輸入",
    "T": "是",
    "F": "否",
    "CHILD": "否",
    "ADULT": "是"
  };
 
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;
  var isEcho = message.is_echo;
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    messageText = quickReplyPayload;
  }

  if (messageText) {
    if (typeof search[senderID] == 'undefined')
      search[senderID] = {};
    if(start[senderID] != 87 ){
      switch (messageText) {
        case '開始':
          sendTextMessage(senderID, "查詢開始！\n接下來的問題如果你覺得無所謂都可以，請回答[都可]兩字，若有按鈕選項請按按鈕來回覆");
          setTimeout(function(){ sendQuickReply(senderID, "請問你想領養甚麼寵物？", ["狗", "貓"]); }, 2000);
          start[senderID] = 87;
          step[senderID] = 1;
          break;
        default:
          sendTextMessage(senderID, "你好！我是動物領養資訊站的小幫手，我可以幫助你查詢適合你領養的寵物喔！\n只要輸入[開始]這兩個字就能開始查詢~ ");
      }
    } else if(start[senderID]==87){
      if(step[senderID] == 1){//取得動物類型
        search[senderID].kind = messageText;
        sendQuickReply(senderID, "寵物的性別？", ["公", "母" , "都可"]);
        step[senderID] = 2;
      } else if(step[senderID] == 2){//取得動物性別
        search[senderID].sex = messageText;
        sendQuickReply(senderID, "寵物的體型？", ["迷你", "大型", "中型", "小型", "都可"]);
        step[senderID] = 3;
      } else if(step[senderID] == 3){//取得動物體型
        search[senderID].bodytype = messageText;
        sendQuickReply(senderID, "寵物是否成年？", ["是", "否", "都可"]);
        step[senderID] = 4;
      } else if(step[senderID] == 4){//取得動物年紀
        search[senderID].age = messageText;
        sendTextMessage(senderID, "寵物的毛色？\n（簡短比較有利搜尋）");
        step[senderID] = 5;
      } else if(step[senderID] == 5){//取得動物毛色
        search[senderID].colour = messageText;
        sendTextMessage(senderID, "寵物所在的地點？\n（簡短比較有利搜尋）");
        step[senderID] = 6;
      } else if(step[senderID] == 6){//取得動物地點
        search[senderID].place = messageText;
        sendTextMessage(senderID, "詢問完成、開始查詢~~~");
        query_count[senderID] = 0;
        req = "";
        var _request = http.get("http://data.coa.gov.tw/Service/OpenData/AnimalOpenData.aspx", function(response) {
          response.on('data', function (chunk) {
            req += chunk;
          });
          response.on('end', function() {
            req = JSON.parse(req);
            sendTextMessage(senderID, "搜尋結果如下：");
            setTimeout(function(){ find(senderID); }, 2000);
            step[senderID] = 7;
          });
        });
        _request.on("error", function(err) {
          console.log(err);
        });
      } else if(step[senderID] == 7){
        if (messageText == '我想領養') {
          text[senderID] = Math.random().toString(36).substring(11);
          //sendTextMessage(senderID, "我們即將幫您公告，請輸入驗證碼：");
          //sendImageMessage(senderID, "https://messager-linsyee.c9users.io/img/" + text[senderID] + ".jpg");
          autoPost(req, query_count[senderID]);
        }
        if (messageText == '是')
          find(senderID);
        else {
          step[senderID] = 0;
          start[senderID]=0;
          sendTextMessage(senderID, "你好！我是動物領養資訊站的小幫手，我可以幫助你查詢適合你領養的寵物喔！\n只要輸入[開始]這兩個字就能開始查詢~ ");
        }
      }
    } 
    
  } else if (messageAttachments) {
    sendTextMessage(senderID, "怕.jpg");
  }
}

function find(senderID) {
  for (var i = query_count[senderID], c = 0; i < req.length; i++, c = 0) {
    if (search[senderID].kind == "都可" || req[i].animal_kind.match(search[senderID].kind) != null)
      c++;
    if (search[senderID].sex == "都可" || pattern[req[i].animal_sex] == search[senderID].sex)
      c++;
    if (search[senderID].bodytype == "都可" || pattern[req[i].animal_bodytype] == search[senderID].bodytype)
      c++;
    if (search[senderID].age == "都可" || _pattern[req[i].animal_age] == search[senderID].age)
      c++;
    if (search[senderID].colour == "都可" || req[i].animal_colour.match(search[senderID].colour) != null)
      c++;
    if (search[senderID].place == "都可" || req[i].animal_place.match(search[senderID].place) != null)
      c++;
    if (c == 6)
    {
      query_count[senderID] = i+1;
      sendImageMessage(senderID, req[i].album_file);
      setTimeout(function(){ sendTextMessage(senderID, req[i].animal_remark); }, 2000);
      setTimeout(function(){ sendTextMessage(senderID, "小檔案\n動物編號：" + req[i].animal_id + "\n區域編號：" + req[i].animal_subid + "\n狀態：" + pattern[req[i].animal_status] + "\n類型：" + req[i].animal_kind + "\n性別：" + pattern[req[i].animal_sex] + "\n體型：" + pattern[req[i].animal_bodytype] + "\n年紀：" + pattern[req[i].animal_age] + "\n毛色：" + req[i].animal_colour + "\n尋獲地點：" + req[i].animal_foundplace + "\n目前所在地點：" + req[i].animal_place + "\n是否結紮：" + _pattern[req[i].animal_sterilization] + "\n是否已施打狂犬病疫苗：" + _pattern[req[i].animal_bacterin] + "\n開放認養起始日期：" + req[i].animal_opendate + "\n開放認養截止日期：" + req[i].animal_closeddate + "\n資料更新日期：" + req[i].animal_update); }, 4000);
      setTimeout(function(){ sendTextMessage(senderID, "聯絡資訊\n收容所名稱：" + req[i].shelter_name + "\n收容所地址：" + req[i].shelter_address + "\n聯絡電話：" + req[i].shelter_tel); }, 6000);
      setTimeout(function(){ sendQuickReply(senderID, "是否顯示下一筆資料？\n若想領養該寵物，請按 [我想領養]，我們將結束搜尋並發文~~", ["是", "否", "我想領養"]); }, 8000);
      return;
    }
  }
  sendTextMessage(senderID, "已無符合搜尋條件的寵物了");
  step[senderID] = 0;
  start[senderID]=0;
}

function sendQuickReply(recipientId, query_text, text) {
  var q = [];
  for (var i = 0; i < text.length; i++)
  {
    q[i] = {
      content_type:"text",
      title: text[i],
      payload: text[i]
    };
  }
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: query_text,
      metadata: "DEVELOPER_DEFINED_METADATA",
      quick_replies: q
    }
  };

  callSendAPI(messageData);
}

function receivedDeliveryConfirmation(event) {
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s", 
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}

function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " + 
    "at %d", senderID, recipientID, payload, timeOfPostback);

  sendTextMessage(senderID, "Postback called");
}

function receivedMessageRead(event) {
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

function sendImageMessage(recipientId, query_url) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: query_url
        }
      }
    }
  };

  callSendAPI(messageData);
}

function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;
    } else {
      console.error(response.error);
    }
  });  
}

function autoPost(req, index) {
  var pageId = "1071972299547635";
  var token = "EAAPOk2glmqEBAOZBc1HU2T8oQGxC4DcGmkuLhgfJf6RPt0E5hZAR749oZA6nrMtOaYGMTP93WZBiH86OemQz5FFS0qaaqFvZAFyL8mUKrYJHfTZBZCzIZCK4UZAhQauUO8JCS4AE0tIlfYZCyITi6OYtELPaW6rme48AU9ZCQh7pbHesQZDZD";
  
  FB.setAccessToken(token);
  FB.api('/' + pageId, {fields: token}, function(resp) {
    FB.api('/' + pageId + '/feed',
      'post',
      {// things that we are going to post
        picture: req[index - 1].album_file, // animal picture
        link: req[index - 1].album_file,
        message: "\nHello everyone I have been adopt~~~~\n\n\n" + req[index].animal_remark + "小檔案\n動物編號：" + req[index - 1].animal_id + "\n區域編號：" + req[index - 1].animal_subid + "\n狀態：" + pattern[req[index - 1].animal_status] + "\n類型：" + req[index - 1].animal_kind + "\n性別：" + pattern[req[index - 1].animal_sex] + "\n體型：" + pattern[req[index - 1].animal_bodytype] + "\n年紀：" + pattern[req[index - 1].animal_age] + "\n毛色：" + req[index - 1].animal_colour + "\n尋獲地點：" + req[index - 1].animal_foundplace + "\n目前所在地點：" + req[index - 1].animal_place + "\n是否結紮：" + _pattern[req[index - 1].animal_sterilization] + "\n是否已施打狂犬病疫苗：" + _pattern[req[index - 1].animal_bacterin] + "\n",
        access_token: resp.access_token
      }
      ,function(response) {
      console.log(response);
      });
  });
}

app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;