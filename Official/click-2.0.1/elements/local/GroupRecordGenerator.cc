#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "GroupRecordGenerator.hh"
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>

#include <time.h>
#include <stdlib.h>
#include <iostream>

using namespace std;

CLICK_DECLS
GroupReportGenerator::GroupReportGenerator(){
	f_makingPacket = false;
}

GroupReportGenerator::~GroupReportGenerator(){}

void GroupReportGenerator::makeNewPacket(uint8_t reportType){
	/// Makes the packet, well not really, but the user thinks i will
	f_groupRecordList.clear();
	f_sourceListPerRecord.clear();
	f_reportType = reportType;
	f_makingPacket = true;
}

bool GroupReportGenerator::addGroupRecord(uint8_t type, uint8_t auxDataLen, struct in_addr multicastAddress,
	Vector<struct in_addr> sources){
	/// Adds a group record to the currently "queued" packet

	if (! f_makingPacket){
		return false;
	}

	struct GroupRecordStatic record = {type, auxDataLen, sources.size(), multicastAddress};
	f_groupRecordList.insert(f_groupRecordList.end(), record);
	f_sourceListPerRecord.insert(f_sourceListPerRecord.end(), sources);
}

Packet* GroupReportGenerator::getCurrentPacket() const{
	/// Get the current resulting packet, if it's invalid, this will return 0


	if (! f_makingPacket){
		return 0;
	}

	if (f_sourceListPerRecord.size() != f_sourceListPerRecord.size() && !SUPPRESS_OUTPUT){
		printf("Warning in report message: no equal amount of source lists and records.\n");
	}

	int headroom = sizeof(click_ether) + sizeof(click_ip);
	int totalPacketSize = 0;
	uint16_t recordAmount = f_groupRecordList.size();
	bool emptySourceLists = true;

	for (int i = 0; i < f_sourceListPerRecord.size(); i++){
		if (f_sourceListPerRecord.at(i).size() > 0){
			emptySourceLists = false;
			break;
		}
	}

	if (!emptySourceLists and !SUPPRESS_OUTPUT){
		printf("WARNING: no support for non-empty source list in membership report message.\n");
	}

	/// From this point on, source lists will be ignored!!
	totalPacketSize += sizeof(struct GroupReportStatic);
	totalPacketSize += sizeof(struct GroupRecordStatic) * f_groupRecordList.size();

    WritablePacket *q = Packet::make(headroom, 0, totalPacketSize, 0);

    if (!q)
		return 0;
    memset(q->data(), '\0', totalPacketSize);

    /// Get and set the group report header
	struct GroupReportStatic* reportHeader = (struct GroupReportStatic *)q->data();
	reportHeader->reportType = 0x22;
	reportHeader->reserved1 = 0;
	reportHeader->checksum = 0;
	reportHeader->reserved2 = 0;
	reportHeader->nrOfRecords = htons(f_groupRecordList.size());

	for (int i = 0; i < f_groupRecordList.size(); i++){
		struct GroupRecordStatic *record = (struct GroupRecordStatic *)(reportHeader + i + 1);
		record->recordType = f_groupRecordList.at(i).recordType;
		record->auxDataLen = f_groupRecordList.at(i).auxDataLen;
		record->nrOfSources = f_groupRecordList.at(i).nrOfSources;
		record->multicastAddress = f_groupRecordList.at(i).multicastAddress;
	}
	
	reportHeader->checksum = click_in_cksum((const unsigned char *)reportHeader, totalPacketSize);

	return q;
}





GroupReportParser::GroupReportParser(){}
GroupReportParser::~GroupReportParser(){}

void GroupReportParser::parsePacket(Packet* packet){
	f_groupRecordList.clear();
	f_sourceListPerRecord.clear();
    /// get the IP header
	click_ip *ipHeader = (click_ip *)packet->data();
    f_src = ipHeader->ip_src;
    f_dst = ipHeader->ip_dst;

    /// Get the group report header
	struct GroupReportStatic* reportHeader = (struct GroupReportStatic *)(ipHeader + 1);
	uint16_t nrOfRecords = ntohs(reportHeader->nrOfRecords);

	for (int i = 0; i < nrOfRecords; i++){
		struct GroupRecordStatic *record = (struct GroupRecordStatic *)(reportHeader + i + 1);

		struct GroupRecordStatic newRecord;
		newRecord.recordType = record->recordType;
		newRecord.auxDataLen = record->auxDataLen;
		newRecord.nrOfSources = record->nrOfSources;
		newRecord.multicastAddress = record->multicastAddress;

		f_groupRecordList.insert(f_groupRecordList.end(), newRecord);
	}
}

Vector<struct GroupRecordStatic> GroupReportParser::getGroupRecords() const{
	return f_groupRecordList;
}


IPAddress GroupReportParser::getSRC() const{
	return f_src;
}

IPAddress GroupReportParser::getDST() const{
	return f_dst;
}

void GroupReportParser::printPacket() const{
	for (int i = 0; i < f_groupRecordList.size(); i++){
		const struct GroupRecordStatic *record = &f_groupRecordList.at(i);

		struct GroupRecordStatic newRecord;
		
		int datalen = newRecord.auxDataLen;
		int nrsources = newRecord.nrOfSources;
		int type = newRecord.recordType;
		cout << ("RECORD:\n");
		cout << ("\tTYPE ");
		cout << "\t" << type << endl;
		cout << ("\tAUX ");
		cout << "\t" << datalen << endl;
		cout << ("\tsourceAmt ");
		cout << "\t" << nrsources << endl;
	}
}


GroupReportGeneratorElement::GroupReportGeneratorElement(){}

GroupReportGeneratorElement::~GroupReportGeneratorElement(){}

int GroupReportGeneratorElement::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
	
	Timer *timer = new Timer(this);
	timer->initialize(this);
	timer->schedule_after_msec(1000);
	return 0;
}

void GroupReportGeneratorElement::push(int port, Packet* p){
	click_chatter("received packet on genElement");
}

Packet* GroupReportGeneratorElement::make_packet(){
	srand(time(0));
	int filterMode = rand() % 2 + 1;

	GroupReportGenerator gen;
	gen.makeNewPacket(REPORTMESSAGE);
	gen.addGroupRecord(4, 0, IPAddress("230.0.0.1").in_addr(), Vector<struct in_addr>());
	Packet* result = gen.getCurrentPacket();
	return result;
}

void GroupReportGeneratorElement::run_timer(Timer *timer)
{
    if (Packet *q = make_packet()) {
 		output(0).push(q);
 		///timer->reschedule_after_msec(1000);
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(GroupReportGeneratorElement)