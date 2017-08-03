#ifndef CLICK_GROUPRECORDGENERATOR_HH
#define CLICK_GROUPRECORDGENERATOR_HH

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>


#ifndef MODE_IS_INCLUDE
#define MODE_IS_INCLUDE 1
#endif

#ifndef MODE_IS_EXCLUDE
#define MODE_IS_EXCLUDE 2
#endif

#ifndef CHANGE_TO_INCLUDE
#define CHANGE_TO_INCLUDE 3
#endif

#ifndef CHANGE_TO_EXCLUDE
#define CHANGE_TO_EXCLUDE 4
#endif

#ifndef REPORTMESSAGE
#define REPORTMESSAGE 0x22
#endif

#ifndef QUERYMESSAGE
#define QUERYMESSAGE 0x11
#endif

#ifndef SUPPRESS_OUTPUT
#define SUPPRESS_OUTPUT false
#endif

#ifndef REPORTMESSAGE
#define REPORTMESSAGE 0x22
#endif


CLICK_DECLS

struct GroupRecordStatic{
	uint8_t recordType;
	uint8_t auxDataLen;
	uint16_t nrOfSources;
	struct in_addr multicastAddress;
};

struct GroupReportStatic{
	uint8_t reportType;
	uint8_t reserved1;
	uint16_t checksum;
	uint16_t reserved2;
	uint16_t nrOfRecords;
};

class GroupReportGenerator{
	// Doesn't set IP header!!! use IPEncap(2, SRC, DST) after this
public:
	GroupReportGenerator();
	~GroupReportGenerator();

	void makeNewPacket(uint8_t reportType);
		/// Makes the packet
	bool addGroupRecord(uint8_t type, uint8_t auxDataLen, struct in_addr multicastAddress, Vector<struct in_addr> sources);
		/// Adds a group record to the currently "queued" packet
	Packet* getCurrentPacket() const;
		/// Get the current resulting packet, if it's invalid, this will return 0

private:

	Vector<struct GroupRecordStatic> f_groupRecordList;
	Vector<Vector<struct in_addr> > f_sourceListPerRecord;

	uint8_t f_reportType;
	bool f_makingPacket;
};

class GroupReportParser{
	/// Assumes valid IP header
public:
	GroupReportParser();
	~GroupReportParser();

	void parsePacket(Packet* packet);

	Vector<struct GroupRecordStatic> getGroupRecords() const;
	IPAddress getSRC() const;
	IPAddress getDST() const;
	//void printPacket() const;

private:

	Vector<struct GroupRecordStatic> f_groupRecordList;
	Vector<Vector<struct in_addr> > f_sourceListPerRecord;

	IPAddress f_src;
	IPAddress f_dst;
};

class GroupReportGeneratorElement: public Element{
public:
	GroupReportGeneratorElement();
	~GroupReportGeneratorElement();
	
	const char *class_name() const	{ return "GroupReportGeneratorElement"; }
	const char *port_count() const	{ return "0/1"; }
	const char *processing() const	{ return PUSH; }
	int configure(Vector<String>&, ErrorHandler*);
	
	void push(int port, Packet* p);
};

CLICK_ENDDECLS

#endif