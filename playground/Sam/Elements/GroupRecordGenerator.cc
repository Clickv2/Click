#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "GroupRecordGenerator.hh"
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>

CLICK_DECLS


GroupRecordGenerator::GroupRecordGenerator(){
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

bool GroupRecordGenerator::initNewRecord(uint8_t recordType, uint8_t auxDataLen, uint16_t nrOfSources, struct in_addr multicastAddress){
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
		return 0;
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





GroupReportGenerator::GroupReportGenerator(){}

GroupReportGenerator::~GroupReportGenerator(){}

int GroupReportGenerator::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, "SRC", cpkM, cpIPAddress, &f_src, "DST", cpkM, cpIPAddress, &f_dst, cpEnd) < 0) return -1;
	
	Timer *timer = new Timer(this);
	timer->initialize(this);
	timer->schedule_after_msec(1000);
	return 0;
}

Packet* GroupReportGenerator::make_packet(){
	int headroom = sizeof(click_ether);

	uint16_t records = 1;

    WritablePacket *q = Packet::make(headroom, 0, sizeof(click_ip) + sizeof(struct GroupReport) + sizeof(struct GroupRecord) * records, 0);
    if (!q)
		return 0;
    memset(q->data(), '\0', sizeof(click_ip) + sizeof(struct GroupReport) + sizeof(struct GroupRecord) * records);

	click_ip *iph1 = (click_ip *)q->data();
	
    iph1->ip_v = 4;
    iph1->ip_hl = sizeof(click_ip) >> 2;
    iph1->ip_len = htons(q->length());
    uint16_t ip_id = ((records) % 0xFFFF) + 1; // ensure ip_id != 0
    iph1->ip_id = htons(ip_id);
    iph1->ip_p = IP_PROTO_IGMP;
    iph1->ip_ttl = 1;
    iph1->ip_src = f_src;
    iph1->ip_dst = f_dst;
    iph1->ip_sum = click_in_cksum((unsigned char *)iph1, sizeof(click_ip));

	struct GroupReport *iph = (struct GroupReport *)(iph1 + 1);
	iph->reportType = 0x22;
	iph->reserved1 = 0;
	iph->checksum = 0;
	iph->reserved2 = 0;
	iph->nrOfRecords = htons(records);

	struct GroupRecord *record = (struct GroupRecord *)(iph + 1);
	record->recordType = MODE_IS_INCLUDE;
	record->auxDataLen = 0;
	record->nrOfSources = 0;
	record->multicastAddress = f_dst.in_addr();
	
	iph->checksum = click_in_cksum((const unsigned char *)iph, sizeof(GroupReport) + sizeof(struct GroupRecord) * records);
	
	q->set_dst_ip_anno(f_dst);
	
	return q;
}

void GroupReportGenerator::run_timer(Timer *timer)
{
    if (Packet *q = make_packet()) {
 	   output(0).push(q);
 	   ///timer->reschedule_after_msec(1000);
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(GroupReportGenerator)