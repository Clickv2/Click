#ifndef CLICK_GROUPQUERYGENERATOR_HH
#define CLICK_GROUPQUERYGENERATOR_HH

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>

#include "GroupRecordGenerator.hh"

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

struct GroupQueryStatic{
	uint8_t queryType;
	uint8_t maxRespCode;
	uint16_t checksum;
	struct in_addr multicastAddress;
	uint8_t Resv_S_QRV;
		/// I had to group them, please take care
	uint8_t QQIC;
	uint16_t nrOfSources;
};

class GroupQueryGenerator{
	/// Yes this could be a standalone function, but it's better this way if you plan to expand the protocol
public:
	GroupQueryGenerator();
	~GroupQueryGenerator();

	Packet* makeNewPacket(uint8_t maxRespCode, bool SFlag, uint8_t QRV, uint8_t QQIC, IPAddress src, IPAddress dst);
		/// Makes the packet if it's invalid, this will return 0
		/// assumes 0 sources!!!
};

class GroupQueryGeneratorElement: public Element{
public:
	GroupQueryGeneratorElement();
	~GroupQueryGeneratorElement();
	
	const char *class_name() const	{ return "GroupQueryGeneratorElement"; }
	const char *port_count() const	{ return "0/1"; }
	const char *processing() const	{ return PUSH; }
	int configure(Vector<String>&, ErrorHandler*);
	
	void run_timer(Timer *);

private:		
	Packet* make_packet();

	IPAddress f_src;
	IPAddress f_dst;
};

CLICK_ENDDECLS

#endif