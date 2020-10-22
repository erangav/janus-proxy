#! /bin/bash
CURL_CMD='curl -v -i -X POST http://10.45.35.203:8088/janus/'
#$CURL_CMD -d '{   "janus": "create",   "transaction": "SRdfYA1Y95ay"}'


#session=$1
session=`$CURL_CMD -d '{   "janus": "create",   "transaction": "SRdfYA1Y95ay"}' 2>&1 | grep '"id": ' | awk '{print $2'}`

echo  ">>> SEssion: $session"


HANDLE_BODY=`echo '{   "janus": "attach",   "plugin": "janus.plugin.nosip",   "opaque_id": "nosiptest-caller-ELDB6mjbnPfL",   "transaction": "jtaEnl9cBhdT", "session_id": '$session' }'`

handle=`$CURL_CMD -d "$HANDLE_BODY" 2>&1 | grep '"id": ' | awk '{print $2'}`
echo  ">>> Handle $handle"


#SDP_FROM_FILE=`cat sdp_a1_v1 `
OFFER_SDP_FROM_FILE=`cat offer.sdp`

OFFER_BODY=`echo '{"janus": "message", "body" : {"request" : "generate", '\
'   "update": false '\
'}, '\
'   "jsep": {' \
'      "type": "offer",'\
'      "sdp": "'$OFFER_SDP_FROM_FILE'"'\
'} , "transaction": "CUGeJkCneMu9", "session_id" : '$session', "handle_id" :  '$handle'}'`


echo "#####################################################"
echo ""

echo "will be send : "
echo $OFFER_BODY
echo ""


echo "#####################################################"
echo "##########        OFFER_BODY      ###################"
echo "#####################################################"
echo ""
echo ""

curl -v  http://10.45.35.203:8088/janus/$session/$handel -H"Origin: http://127.0.0.1:81 Content-Type: application/json" -d "$OFFER_BODY"  --keepalive-time 10

echo "#####################################################"


ANSWER_SDP_FROM_FILE=`cat answer.sdp`

ANSWER_BODY=`echo '{"janus": "message", "body" : {"request" : "process", '\
'   "update": false ',\
'   "type": "answer",'\
'   "sdp": "'$ANSWER_SDP_FROM_FILE'"'\
'} , "transaction": "CwGeJkCneMu9", "session_id" : '$session', "handle_id" :  '$handle'}'`

sleep 3

echo "#####################################################"
echo ""

echo "will be send : "
echo $ANSWER_BODY
echo ""


echo "#####################################################"
echo "######      ANSWER_BODY      ########################"
echo "#####################################################"
echo ""
echo ""

curl -v  http://10.45.35.203:8088/janus/$session/$handel -H"Origin: http://127.0.0.1:81 Content-Type: application/json" -d "$ANSWER_BODY"  --keepalive-time 10

echo "#####################################################"




KEEP_ALIVE_BODY=`echo  '{   "janus": "keepalive",   "session_id": '$session',   "transaction": "CUGeJkCneMu9" }'  `

while true 
do
    sleep 5
    $CURL_CMD -d "$KEEP_ALIVE_BODY"
done