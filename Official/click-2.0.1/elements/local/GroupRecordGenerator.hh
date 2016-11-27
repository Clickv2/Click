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


/*class GroupRecordGenerator{
public:
	GroupRecordGenerator();
	~GroupRecordGenerator();

	bool initNewRecord(uint8_t recordType, uint8_t auxDataLen, uint16_t nrOfSources, struct in_addr multicastAddress);
		/// Since we work with a vector, the number of sources isn't actually needed
		/// BUT the size of the vector can be greater than the size of an uint16_t
		/// I'm sure you can easily check for that, but this way had the most advantages
	bool addSourceAddress(struct in_addr unicastAddress);

	struct GroupRecord getCurrentRecord() const;
		/// Note: this returns a copy of the current made record
		/// This grouprecord is now responsible for deleting itself properly
		/// returns a nullpointer if the current record would be invalid

	Vector<struct in_addr> getCurrentSourceList() const;

	bool setRecordType(int8_t recordType);
private:
	void flushPreviousRecord();

	uint8_t f_recordType;
	uint8_t f_auxDataLen;
	uint16_t f_nrOfSources;
	struct in_addr f_multicastAddress;
	Vector<struct in_addr> f_sourceList;

	uint16_t f_addressesGiven;
	bool f_makingRecord;
};*/

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

	void run_timer(Timer *);

private:		
	Packet* make_packet();

	Vector<struct GroupRecordStatic> f_groupRecordList;
};

CLICK_ENDDECLS

#endif