#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "GroupRecordGenerator.hh"
#include "GroupQueryGenerator.hh"
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>

#include <time.h>
#include <stdlib.h>
#include <iostream>

using namespace std;

CLICK_DECLS

GroupQueryGenerator::GroupQueryGenerator(){}

GroupQueryGenerator::~GroupQueryGenerator(){}

Packet* GroupQueryGenerator::makeNewPacket(uint8_t maxRespCode, bool SFlag,
	uint8_t QRV, uint8_t QQIC, IPAddress src, IPAddress dst){

	if (QRV > 7){
		return 0;
	}

	int headroom = sizeof(click_ether);
	int totalPacketSize = 0;

	totalPacketSize += sizeof(click_ip);
	totalPacketSize += sizeof(struct GroupQueryStatic);

    WritablePacket *q = Packet::make(headroom, 0, totalPacketSize, 0);

    if (!q)
		return 0;
    memset(q->data(), '\0', totalPacketSize);

    /// get and then set the IP header
	click_ip *ipHeader = (click_ip *)q->data();
    ipHeader->ip_v = 4;
    ipHeader->ip_hl = sizeof(click_ip) >> 2;
    ipHeader->ip_len = htons(q->length());
    /// TODO what's this?
    uint16_t ip_id = ((maxRespCode) % 0xFFFF) + 1; // ensure ip_id != 0
    ipHeader->ip_id = htons(ip_id);
    ipHeader->ip_p = IP_PROTO_IGMP;
    ipHeader->ip_ttl = 1;
    ipHeader->ip_src = src;
    ipHeader->ip_dst = dst;
    ipHeader->ip_sum = click_in_cksum((unsigned char *)ipHeader, sizeof(click_ip));

    /// Get and set the group query header
	struct GroupQueryStatic* queryHeader = (struct GroupQueryStatic *)(ipHeader + 1);
	queryHeader->queryType = 0x11;
	//printf("MRP: %d\n", maxRespCode);
	queryHeader->maxRespCode = (maxRespCode);
	queryHeader->checksum = 0;
	queryHeader->multicastAddress = dst.in_addr();

	uint8_t Resv_S_QRV = QRV;
	if (SFlag){
		Resv_S_QRV += 8;
	}

	//printf("QRV: %d\n", Resv_S_QRV);
	queryHeader->Resv_S_QRV = (Resv_S_QRV);

	//printf("QQIV: %d\n\n", QQIC);
	queryHeader->QQIC = (QQIC);
	queryHeader->nrOfSources = 0;

	queryHeader->checksum = click_in_cksum((const unsigned char *)queryHeader, totalPacketSize - sizeof(click_ip));
	
	q->set_dst_ip_anno(dst);
	
	return q;

}



GroupQueryParser::GroupQueryParser(){}
GroupQueryParser::~GroupQueryParser(){}

void GroupQueryParser::parsePacket(Packet* packet){

	click_ip *ipHeader = (click_ip *)packet->data();
    f_src = ipHeader->ip_src;
    f_dst = ipHeader->ip_dst;

    /// Get and set the group query header
	struct GroupQueryStatic* queryHeader = (struct GroupQueryStatic *)(ipHeader + 1);
	f_maxRespCode = queryHeader->maxRespCode;
	f_multicastAddress = queryHeader->multicastAddress;

	uint8_t Resv_S_QRV = queryHeader->Resv_S_QRV;
	int QRV;
	if (Resv_S_QRV >= 8){
		f_SFlag = true;
		Resv_S_QRV -= 8;
	}else{
		f_SFlag = false;
	}
	f_QRV = Resv_S_QRV;

	//printf("QQIV: %d\n\n", QQIC);
	f_QQIC = queryHeader->QQIC;
}


IPAddress GroupQueryParser::getSRC() const{
	return f_src;
}

IPAddress GroupQueryParser::getDST() const{
	return f_dst;
}


int GroupQueryParser::getMaxRespCode() const{
	return f_maxRespCode;
}

IPAddress GroupQueryParser::getGroupAddress() const{
	return f_multicastAddress;
}

bool GroupQueryParser::getSFlag() const{
	return f_SFlag;
}

int GroupQueryParser::getQRV() const{
	return f_QRV;
}

int GroupQueryParser::getQQIC() const{
	return f_QQIC;
}

void GroupQueryParser::printPacket() const{
	cout << ("DST: ") << this->getDST().unparse() << endl;
	cout << ("Group: ") << this->getGroupAddress().unparse() << endl;
	cout << ("S: ") << this->getSFlag() << endl;
	cout << ("QRV: ") << this->getQRV() << endl;
	cout << ("QQIC: ") << this->getQQIC() << endl;
}




GroupQueryGeneratorElement::GroupQueryGeneratorElement(){}

GroupQueryGeneratorElement::~GroupQueryGeneratorElement(){}

int GroupQueryGeneratorElement::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &f_src, "DST", cpkM, cpIPAddress, &f_dst, cpEnd) < 0) return -1;
	
	Timer *timer = new Timer(this);
	timer->initialize(this);
	timer->schedule_after_msec(1000);
	return 0;
}

Packet* GroupQueryGeneratorElement::make_packet(){
	srand(time(0));
	int rnd = rand() % 2;

	bool SFlag = false;
	if (rnd == 1){
		SFlag = true;
	}else{
		SFlag = false;
	}

	GroupQueryGenerator gen;
	Packet* result = gen.makeNewPacket(128, SFlag, 2, 2, f_src, f_dst);
	return result;
}

void GroupQueryGeneratorElement::run_timer(Timer *timer)
{
    if (Packet *q = make_packet()) {
    	GroupQueryParser parser;
    	parser.parsePacket(q);
    	parser.printPacket();
		output(0).push(q);
		timer->reschedule_after_msec(1000);
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(GroupQueryGeneratorElement)