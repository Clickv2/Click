#ifndef CLICK_GROUPRECORD_HH
#define CLICK_GROUPRECORD_HH

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

#ifndef SUPPRESS_OUTPUT
#define SUPPRESS_OUTPUT false
#endif

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>

#include <limits.h>



CLICK_DECLS


class GroupRecord{
	/// Provides no safety, good for experiments
	/// Us the GroupRecordGenerator for safety though
public:
	GroupRecord(uint8_t recordType, uint8_t auxDataLen, uint16_t nrOfSources,
		struct in_addr multicastAddress, const Vector<click_ip>& sourceAddr);
		/// BUT the size of the vector can be greater than the size of an uint16_t
		/// I'm sure you can easily check for that, but this way had the most advantages
	~GroupRecord();

	uint8_t getType() const;
	uint8_t getAuxDataLen() const;
	uint16_t getNrOfSources() const;
	struct in_addr getMulticastIp() const;
	const Vector<struct in_addr>& getSourceList() const;

private:

	uint8_t f_recordType;
	uint8_t f_auxDataLen;
	uint16_t f_nrOfSources;
	struct in_addr f_multicastAddress;
	Vector<struct in_addr> f_sourceList;
};

struct click_igmp_record {
	uint8_t	igmp_type;
	uint8_t	igmp_auxDataLen;
	uint16_t igmp_nrSources;
	struct in_addr igmp_multicastAddress;
	struct in_addr sourceAddresses[];
};

CLICK_ENDDECLS

#endif