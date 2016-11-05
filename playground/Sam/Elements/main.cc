#include "GroupRecord.hh"
#include "GroupRecordGenerator.hh"

int main(){
	printf("%lu", sizeof(struct click_igmp_record));
	//struct click_igmp_record test = {1, 1, 1, 1, struct in_addr[1]};
	return 0;
}
