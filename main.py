import string
import sys
sys.dont_write_bytecode = True

import base64
import logging

import binascii
import donna25519
import pyqrcode
import websocket
import traceback
import time
import requests

from urllib import parse, request
from utilities import *
from threading import Timer
from datetime import datetime
from whatsapp_binary_reader import whatsappReadBinary
from whatsapp_binary_writer import whatsappWriteBinary
from whatsapp_defines import *;


# WHATSAPP_WEB_VERSION = "2,2121,6"
WHATSAPP_WEB_VERSION = "100,100,100"


def setup_logger(name, log_file, level=logging.INFO):
  handler = logging.FileHandler(log_file)
  handler.setFormatter(logging.Formatter('[%(asctime)s] - %(message)s'))

  logger = logging.getLogger(name)
  logger.setLevel(level)
  logger.addHandler(handler)

  return logger

class WhatsApp:
  ws = None
  clientId = None
  privateKey = None
  publicKey = None
  secret = None
  encKey = None
  macKey = None
  sharedSecret = None
  data = {}
  mydata = {}
  sessionExists = False
  keepAliveTimer = None
  refreshConnectionTimer = None
  reconnect = False
  enableRefresh = False
  messageTraffic = {}
  messageSentCount = 0
  settingsFile = None
  connectionType = "takeover"
  telegramToken = ""
  telegramChatId = ""

  def __init__(self, settingsFile, telegramToken, telegramChatId):
    self.settingsFile = settingsFile
    self.telegramToken = telegramToken
    self.telegramChatId = telegramChatId

  def connect(self, connectionType="takeover"):
    self.connectionType = connectionType
    self.initLocalParams()
    self.ws = websocket.WebSocketApp("wss://web.whatsapp.com/ws",
                                     on_message=lambda ws, msg: self.on_message(ws, msg),
                                     on_error=lambda ws, msg: self.on_error(ws, msg),
                                     on_close=lambda ws, stat, msg: self.on_close(ws, stat, msg),
                                     on_open=lambda ws: self.on_open(ws),
                                     header={"Origin: https://web.whatsapp.com"})
    if self.enableRefresh:
      self.refreshConnectionTimer = Timer(11*60*60, lambda: self.ws.close())
      self.refreshConnectionTimer.start()

    self.ws.run_forever()

  def initLocalParams(self):
    self.data = self.restoreSession()
    keySecret = None
    if self.data is None:
      keySecret = os.urandom(32)
      self.mydata['clientId'] = base64.b64encode(os.urandom(16)).decode("utf-8")
      self.mydata["keySecret"] = base64.b64encode(keySecret).decode("utf-8")
    else:
      self.sessionExists = True
      self.mydata = self.data['myData']
      keySecret = base64.b64decode(self.mydata["keySecret"])

    self.clientId = self.mydata['clientId']
    self.privateKey = donna25519.PrivateKey(secret=keySecret)
    self.publicKey = self.privateKey.get_public()

    if self.sessionExists:
      self.setConnInfoParams(base64.b64decode(self.data["secret"]))

  def setConnInfoParams(self, secret):
    self.secret = secret
    self.sharedSecret = self.privateKey.do_exchange(donna25519.PublicKey(secret[:32]))
    sharedSecretExpanded = HKDF(self.sharedSecret, 80)
    hmacValidation = HmacSha256(sharedSecretExpanded[32:64], secret[:32] + secret[64:])
    if hmacValidation != secret[32:64]:
      raise ValueError("Hmac mismatch")

    keysEncrypted = sharedSecretExpanded[64:] + secret[64:]
    keysDecrypted = AESDecrypt(sharedSecretExpanded[:32], keysEncrypted)
    self.encKey = keysDecrypted[:32]
    self.macKey = keysDecrypted[32:64]

  def sendKeepAlive(self):
    self.ws.send("?,,")
    
    if self.keepAliveTimer is not None:
      self.keepAliveTimer.cancel()

    self.keepAliveTimer = Timer(15, lambda: self.sendKeepAlive())
    self.keepAliveTimer.start()

  def sendTextMessage(self, number, text):
    self.ws.send("?,,")
    messageId = "3EB0" + binascii.hexlify(os.urandom(8)).upper().decode("utf-8")
    messageParams = {"key": {"fromMe": True, "remoteJid": number, "id": messageId},
                     "messageTimestamp": getTimestamp(), "status": 1, "message": {"conversation": text}}
    msgData = ["action", {"type": "relay", "epoch": str(self.messageSentCount)},
               [["message", None, WAWebMessageInfo.encode(messageParams)]]]
    encryptedMessage = WhatsAppEncrypt(self.encKey, self.macKey, whatsappWriteBinary(msgData))
  
    b1 = bytearray(messageId, "utf-8")
    b2 = bytearray(",", "utf-8")
    b3 = bytearray(to_bytes(WAMetrics.MESSAGE, 1),"utf-8")
    b4 = bytearray([0x80])
    b5 = bytearray(encryptedMessage)

    payload = b1 + b2 + b3 + b4 + b5
    
    self.messageSentCount = self.messageSentCount + 1
    self.ws.send(payload, websocket.ABNF.OPCODE_BINARY)

  def saveSession(self, jsonObj):
    jsonObj['myData'] = self.mydata

    if self.sessionExists:
      for key, value in jsonObj.items():
        self.data[key] = value
      jsonObj = self.data

    with open(self.settingsFile, 'w') as outfile:
      json.dump(jsonObj, outfile)

  def restoreSession(self):
    if (os.path.exists(self.settingsFile)):
      with open(self.settingsFile) as file:
        data = json.load(file)
        return data
    return None

  def sendTelegramText(self, message):
    requests.get(f"https://api.telegram.org/bot{self.telegramToken}/sendMessage?chat_id={self.telegramChatId}&text={message}")
                
  def sendTelegramPhoto(self, path):
    files = {'photo': open(path, 'rb')}
    requests.post(f'https://api.telegram.org/bot{self.telegramToken}/sendPhoto?chat_id={self.telegramChatId}', files=files)

  def handleBinaryMessage(self, message):
    checkSum = message[:32]
    hashHMAC = HmacSha256(self.macKey, message[32:])

    if hashHMAC != checkSum:
      logging.info("Invalid Checksum")
      return

    decryptedMessage = AESDecrypt(self.encKey, message[32:])
    processedData = whatsappReadBinary(decryptedMessage, True)

    try:
      if(processedData[0] == "action") and (processedData[1]["add"] == "relay"):
          wdict:dict = dict(processedData[2][0])
          remoteJid:string = wdict["key"]["remoteJid"]
          fromMe:bool = wdict["key"]["fromMe"]
          id:string = wdict["key"]["id"]
          messageOriginalTimestamp: float = float(wdict["messageTimestamp"])
          messageTimestamp:int = int(wdict["messageTimestamp"])
          currentTimestamp:int = int(time.time())
          conversation:string = ""
          if("conversation" in  wdict["message"]):
              conversation =  wdict["message"]["conversation"]

          flagAllowMessageDelivery = (not fromMe) and ("@s.whatsapp.net" in remoteJid) and not ("-" in remoteJid)
          flagAllowMessageDelivery &= ( (int)(currentTimestamp - messageTimestamp) / 60 ) < 15

          if flagAllowMessageDelivery:
            flagFinalTestToSend = False
            if remoteJid in self.messageTraffic:
                if (currentTimestamp - self.messageTraffic[remoteJid] > 5):
                    self.messageTraffic[remoteJid] = currentTimestamp
                    flagFinalTestToSend = True
            else:
                self.messageTraffic[remoteJid] = currentTimestamp
                flagFinalTestToSend = True

            if flagFinalTestToSend == True:
                self.sendTextMessage(remoteJid, "@message redirected to: */telegram/*.\n@not online(%sU)." % str(messageTimestamp))

                dateFromTimestamp = datetime.fromtimestamp(messageOriginalTimestamp).strftime('%H:%M:%S')
                telegramTextEncoded = parse.quote(f"{dateFromTimestamp} {remoteJid}': '{conversation}'")
                self.sendTelegramText(telegramTextEncoded)
    except:
      pass

  def handleJsonMessage(self, message, jsonObj, ws):
    if 'ref' in jsonObj:
      if self.sessionExists is False:
        serverRef = jsonObj["ref"]
        qrCodeContents = serverRef + "," + base64.b64encode(self.publicKey.public).decode("utf-8") + "," + self.clientId
        img = pyqrcode.create(qrCodeContents, error='L')
        img.png("qrcode.png")
        print("Qrcode was sent via telegram")
        self.sendTelegramText("!!Whatsapp waits for the qrcode scan!")
        self.sendTelegramPhoto("qrcode.png")
    elif isinstance(jsonObj, list) and len(jsonObj) > 0:
      if jsonObj[0] == "Conn":
        logging.info("Connection msg received")
        self.sendKeepAlive()
        if self.sessionExists is False:
          self.setConnInfoParams(base64.b64decode(jsonObj[1]["secret"]))
        self.saveSession(jsonObj[1])

      elif jsonObj[0] == "Cmd":
        logging.info("Challenge received")
        cmdInfo = jsonObj[1]
        if cmdInfo["type"] == "challenge":
          challenge = base64.b64decode(cmdInfo["challenge"])
          sign = base64.b64encode(HmacSha256(self.macKey, challenge)).decode("utf-8")
          messageTag = str(getTimestamp())
          message = ('%s,["admin","challenge","%s","%s","%s"]' % (messageTag, sign, self.data["serverToken"], self.clientId))
          logging.info('message %s' % message)
          self.ws.send(message)
      elif jsonObj[0] == "Presence":
        pass
    elif isinstance(jsonObj, object):
      status = jsonObj["status"]


  def on_open(self, ws):
    messageTag = str(getTimestamp())
    message = messageTag + ',["admin","init",[' + WHATSAPP_WEB_VERSION + '],["Android", "Termux", "10"],"' + self.clientId + '",true]'
    logging.info(message)
    self.ws.send(message)

    if self.data is not None:
      clientToken = self.data["clientToken"]
      serverToken = self.data["serverToken"]
      messageTag = str(getTimestamp())
      message = ('%s,["admin","login","%s","%s","%s","%s"]' % (
        messageTag, clientToken, serverToken, self.clientId, self.connectionType))
      logging.info(message)
      self.ws.send(message)
    else:
      logging.info("No data")

  def on_message(self, ws, message):
    try:
      if isinstance(message, str):
        messageSplit = message.split(",", 1)
      else:
        messageSplit = message.split(b",", 1)

      if len(messageSplit) == 1:
        logging.info(message)
        return

      messageTag = messageSplit[0]
      messageContent = messageSplit[1]

      if isinstance(message, str):
        try:
          jsonObj = json.loads(messageContent)
          self.handleJsonMessage(message, jsonObj, ws)
        except:
          pass
      else:
        self.handleBinaryMessage(messageContent)

    except:
      logging.info("Some error encountered")
      traceback.print_exc()
      self.ws.close()
      raise

  def on_error(self, ws, error):
    logging.info(error)

  def on_close(self, ws, stat, msg):
    if self.keepAliveTimer is not None:
      self.keepAliveTimer.cancel()
    if self.refreshConnectionTimer is not None:
      self.refreshConnectionTimer.cancel()
    if self.reconnect:
      wa.connect("takeover")


if __name__ == "__main__":
  dataDir = "./data"
  settingsFile = dataDir + '/settings.json'
  loggingFile = dataDir + "/info.log"
  telegramToken = ""
  telegramChatId = ""

  if not os.path.exists(dataDir):
    os.makedirs(dataDir)

  logging.basicConfig(filename=loggingFile,
                      format='[%(asctime)s] {%(filename)s:%(lineno)d} - %(message).300s', level=logging.INFO,
                      filemode='a')

  wa = WhatsApp(settingsFile, telegramToken, telegramChatId)
  wa.connect()