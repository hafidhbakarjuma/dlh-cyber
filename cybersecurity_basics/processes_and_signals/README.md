# process and signals

This project is about managing Linux processes and signals using Bash scripts.

How it works

A process is a running program on your system. Every process has a unique PID (Process ID).

A signal is a message sent to a process to tell it what to do (stop, pause, restart).


Scripts

0. My PID

0-what-is-my-pid	displays the PID of the current script.

1. List your processes

1-list_your_processes	displays all running processes for all users in a tree/hierarchy view.

Uses ps auxf — shows parent and child processes with their relationship.

2. Show your Bash PID

2-show_your_bash_pid	displays lines containing the word bash from the process list.

Useful to quickly find your Bash process PID.

Cannot use pgrep. Uses ps auxf with grep.

3. Show your Bash PID made easy

3-show_your_bash_pid_made_easy	displays PID and name of all bash processes.

Cannot use ps. Uses pgrep -l.

4. To infinity and beyond

4-to_infinity_and_beyond	runs forever printing a message every 2 seconds.

Stop it with CTRL+C or kill.

5. Stop me if you can

5-dont_stop_me_now 	stops the 4-to_infinity_and_beyond process.

6. Stop me if you can (without kill)

6-stop_me_if_you_can 	stops 4-to_infinity_and_beyond without using kill or killall.

7. Highlander

7-highlander runs forever but ignores SIGTERM — prints I am invincible!!! instead of stopping.

The only way to stop it is SIGKILL.

67. Stop the Highlander

67-stop_me_if_you_can	kills the 7-highlander process using SIGKILL

8. Beheaded process

8-beheaded_process force kills 7-highlander with SIGKILL (-9).

9. Process and PID file

9-process_and_pid_file	saves its PID to /tmp/myscript.pid and handles signals differently:

Signal            How to send            Response

SIGTERM           kill <PID>             Prints message then exits

SIGINT            CTRL+C                 Prints message keeps running

SIGQUIT           CTRL+\                 Deletes PID file and exits


10. Manage my process

manage_my_process 	writes I am alive! to /tmp/my_process every 2 seconds.

10-manage_my_process 	controls it like a service:

bash

sudo ./10-manage_my_process start    # start the process

sudo ./10-manage_my_process stop     # stop the process

sudo ./10-manage_my_process restart  # restart the process

Key Concepts

Concept            Description

PID                Unique ID assigned to every running process

$$                 Special variable — PID of current script

SIGTERM            Politely ask a process to stop (can be trapped)

SIGKILL            Force kill — cannot be trapped or ignored

SIGINT             Signal sent by CTRL+C

SIGQUIT            Signal sent by CTRL+\

trap               Catches signals and runs a custom command
