#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "GroupRecordGenerator.hh"
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>

#include <time.h>
#include <stdlib.h>

CLICK_DECLS


/*GroupRecordGenerator::GroupRecordGenerator(){
	f_recordType = 0;
	f_auxDataLen = 0;
	f_nrOfSources = 0;
	f_addressesGiven = 0;
	f_multicastAddress = IPAddress().in_addr();
	f_makingRecord = false;
}

GroupRecordGenerator::~GroupRecordGenerator(){
	this->flushPreviousRecord();
}

bool GroupRecordGenerator::initNewRecord(uint8_t recordType, uint8_t auxDataLen, uint16_t nrOfSources,
	struct in_addr multicastAddress){
	/// Flush previous record data
	this->flushPreviousRecord();

	/// Set record type if valid
	if (recordType != MODE_IS_INCLUDE || recordType != MODE_IS_EXCLUDE
		|| recordType != CHANGE_TO_INCLUDE || recordType != CHANGE_TO_EXCLUDE){
		return false;
	}
	this->f_recordType = recordType;

	/// Set the auxiliary data length
	this->f_auxDataLen = auxDataLen;

	/// Set the number of sources
	if (!SUPPRESS_OUTPUT && nrOfSources != 0){
		fprintf(stdout, "nrOfSources is non-zero!\n", "%s");
	}
	this->f_nrOfSources = nrOfSources;

	/// Set the multicast address
	this->f_multicastAddress = multicastAddress;

	/// Init an empty source list
	this->f_sourceList.clear();

	/// Indicate that a valid record is being made
	f_makingRecord = true;

	return true;
}

bool GroupRecordGenerator::addSourceAddress(struct in_addr unicastAddress){
	f_sourceList.insert(f_sourceList.end(), unicastAddress);
	f_addressesGiven++;
	return true;
}

GroupRecord* GroupRecordGenerator::getCurrentRecord() const{
	/// Note: this returns a copy of the current made record
	/// This grouprecord is now responsible for deleting itself properly
	/// returns a nullpointer if the current record would be invalid
	if (f_makingRecord && f_addressesGiven == f_sourceList.size()){
		/// TODO adjust this to a correct record
		return struct GroupRecordStatic(f_recordType, f_auxDataLen, f_nrOfSources, f_multicastAddress);
	}else{
		return 0;
	}
}

void GroupRecordGenerator::flushPreviousRecord(){
	f_recordType = 0;
	f_auxDataLen = 0;
	f_nrOfSources = 0;
	f_addressesGiven = 0;
	f_multicastAddress = IPAddress().in_addr();
	f_makingRecord = false;
}


Vector<struct in_addr> GroupRecordGenerator::getCurrentSourceList() const{
	if (f_makingRecord && f_addressesGiven == f_sourceList.size()){
		return f_sourceList;
	}else{
		return 0;
	}
}*/


GroupReportGenerator::GroupReportGenerator(){
	f_makingPacket = false;
}

GroupReportGenerator::~GroupReportGenerator(){}

void GroupReportGenerator::makeNewPacket(uint8_t reportType, IPAddress src, IPAddress dst){
	/// Makes the packet, well not really, but the user thinks i will
	f_groupRecordList.clear();
	f_sourceListPerRecord.clear();
	f_reportType = reportType;
	f_src = src;
	f_dst = dst;
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

	int headroom = sizeof(click_ether);
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
	printf("test\n");
	totalPacketSize += sizeof(click_ip);
	totalPacketSize += sizeof(struct GroupReportStatic);
	totalPacketSize += sizeof(struct GroupRecordStatic) * f_groupRecordList.size();

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
    uint16_t ip_id = ((f_groupRecordList.size()) % 0xFFFF) + 1; // ensure ip_id != 0
    ipHeader->ip_id = htons(ip_id);
    ipHeader->ip_p = IP_PROTO_IGMP;
    ipHeader->ip_ttl = 1;
    ipHeader->ip_src = f_src;
    ipHeader->ip_dst = f_dst;
    ipHeader->ip_sum = click_in_cksum((unsigned char *)ipHeader, sizeof(click_ip));

	printf("test1\n");
    /// Get and set the group report header
	struct GroupReportStatic* reportHeader = (struct GroupReportStatic *)(ipHeader + 1);
	reportHeader->reportType = 0x22;
	reportHeader->reserved1 = 0;
	reportHeader->checksum = 0;
	reportHeader->reserved2 = 0;
	reportHeader->nrOfRecords = htons(f_groupRecordList.size());

	printf("test2\n");
	for (int i = 0; i < f_groupRecordList.size(); i++){
		struct GroupRecordStatic *record = (struct GroupRecordStatic *)(reportHeader + i + 1);
		record->recordType = f_groupRecordList.at(i).recordType;
		record->auxDataLen = f_groupRecordList.at(i).auxDataLen;
		record->nrOfSources = f_groupRecordList.at(i).nrOfSources;
		record->multicastAddress = f_groupRecordList.at(i).multicastAddress;
	}
	
	printf("test3\n");
	reportHeader->checksum = click_in_cksum((const unsigned char *)reportHeader, totalPacketSize - sizeof(click_ip));
	
	q->set_dst_ip_anno(f_dst);
	
	return q;
}


GroupReportGeneratorElement::GroupReportGeneratorElement(){}

GroupReportGeneratorElement::~GroupReportGeneratorElement(){}

int GroupReportGeneratorElement::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &f_src, "DST", cpkM, cpIPAddress, &f_dst, cpEnd) < 0) return -1;
	
	Timer *timer = new Timer(this);
	timer->initialize(this);
	timer->schedule_after_msec(1000);
	return 0;
}

Packet* GroupReportGeneratorElement::make_packet(){
	srand(time(0));
	int filterMode = rand() % 2 + 1;

	GroupReportGenerator gen;
	gen.makeNewPacket(REPORTMESSAGE, f_src, f_dst);
	gen.addGroupRecord(filterMode, 0, f_dst, Vector<struct in_addr>());
	Packet* result = gen.getCurrentPacket();
	return result;
}

void GroupReportGeneratorElement::run_timer(Timer *timer)
{
    if (Packet *q = make_packet()) {
 	   output(0).push(q);
 	   timer->reschedule_after_msec(1000);
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(GroupReportGeneratorElement)