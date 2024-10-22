#ifndef __OFFSET_HPP_
#define __OFFSET_HPP_

namespace Offsets {
uint32_t metaclass_metaclass = 0x0;
uint32_t metaclass_superclass = 0x8;
uint32_t metaclass_vtable = 0x10;

uint32_t proc_p_list_next = 0x0;
uint32_t proc_p_list_prev = 0x8;
uint32_t proc_task = 0x10;
uint32_t proc_p_pid = 0x68;
uint32_t proc_p_ucred = 0xf0;
uint32_t proc_p_fd = 0xf8;
uint32_t proc_p_name = 0x251;
uint32_t proc_p_csflags = 0x280;

uint32_t u_cred_cr_label = 0x78;

uint32_t ipc_port_io_bits = 0x0;
uint32_t ipc_port_io_references = 0x4;
uint32_t ipc_port_ip_messages = 0x18;
uint32_t ipc_port_ip_receiver = 0x60;
uint32_t ipc_port_ip_kobject = 0x68;
uint32_t ipc_port_ip_context = 0x90;
uint32_t ipc_port_ip_srights = 0xa0;

uint32_t ipc_space_is_table = 0x20;

uint32_t task_lck_mtx_type = 0xb;
uint32_t task_active = 0x14;
uint32_t task_vm_map = 0x28;
uint32_t task_next = 0x30;
uint32_t task_prev = 0x38;
uint32_t task_itk_sself = 0x118;
uint32_t task_itk_space = 0x330;
uint32_t task_bsd_info = 0x390;
uint32_t task_t_flags = 0x3d8;
uint32_t task_all_image_info_addr = 0x440;
uint32_t task_all_image_info_size = 0x448;

uint32_t filedesc_fd_ofiles = 0x0;
uint32_t filedesc_fd_cdir = 0x38;
uint32_t filedesc_fd_rdir = 0x40;
uint32_t filedesc_fd_nfiles = 0x48;

uint32_t fileproc_fp_glob = 0x10;
uint32_t fileglob_fg_data = 0x38;

uint32_t PE_state_bootArgs = 0xa0;
}; // namespace Offsets

#endif