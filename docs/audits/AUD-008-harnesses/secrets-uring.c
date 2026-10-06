/* AUD-008: at most two ring entries and one UDP socket, loopback data only. */
#include <errno.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int probe_uring_socket(unsigned short port) {
  struct io_uring_params params = {0};
  int ring = syscall(__NR_io_uring_setup, 2, &params);
  if (ring < 0) { printf("io_uring_setup_errno=%d\n", errno); return 2; }
  size_t sq_size = params.sq_off.array + params.sq_entries * sizeof(unsigned);
  size_t cq_size = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
  if (params.features & IORING_FEAT_SINGLE_MMAP) { if (sq_size < cq_size) sq_size = cq_size; cq_size = sq_size; }
  void *sq = mmap(NULL, sq_size, PROT_READ | PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQ_RING);
  void *cq = (params.features & IORING_FEAT_SINGLE_MMAP) ? sq : mmap(NULL, cq_size, PROT_READ | PROT_WRITE, MAP_SHARED, ring, IORING_OFF_CQ_RING);
  size_t entries_size = params.sq_entries * sizeof(struct io_uring_sqe);
  struct io_uring_sqe *entries = mmap(NULL, entries_size, PROT_READ | PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQES);
  if (sq == MAP_FAILED || cq == MAP_FAILED || entries == MAP_FAILED) { printf("ring_mmap_errno=%d\n", errno); close(ring); return 2; }
  unsigned *tail = (unsigned *)((char *)sq + params.sq_off.tail);
  unsigned *array = (unsigned *)((char *)sq + params.sq_off.array);
  unsigned *mask = (unsigned *)((char *)sq + params.sq_off.ring_mask);
  unsigned index = *tail & *mask;
  struct io_uring_sqe *entry = &entries[index];
  memset(entry, 0, sizeof(*entry));
  entry->opcode = IORING_OP_SOCKET; entry->fd = AF_INET; entry->off = SOCK_DGRAM; entry->len = 0;
  array[index] = index;
  __atomic_store_n(tail, *tail + 1, __ATOMIC_RELEASE);
  int submitted = syscall(__NR_io_uring_enter, ring, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0);
  if (submitted < 0) { printf("io_uring_enter_errno=%d\n", errno); return 2; }
  unsigned *head = (unsigned *)((char *)cq + params.cq_off.head);
  unsigned *cq_mask = (unsigned *)((char *)cq + params.cq_off.ring_mask);
  struct io_uring_cqe *completions = (struct io_uring_cqe *)((char *)cq + params.cq_off.cqes);
  int created = completions[*head & *cq_mask].res;
  printf("io_uring_socket_result=%d\n", created);
  int status = 0;
  if (created >= 0) {
    struct sockaddr_in target = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}};
    const char marker[] = "AUD008 public loopback probe";
    ssize_t sent = sendto(created, marker, sizeof(marker), 0, (struct sockaddr *)&target, sizeof(target));
    printf("uring_socket_loopback_sent_bytes=%zd\n", sent);
    status = sent == sizeof(marker) ? 1 : 2;
    close(created);
  }
  munmap(entries, entries_size);
  if (cq != sq) munmap(cq, cq_size);
  munmap(sq, sq_size); close(ring);
  return status;
}
