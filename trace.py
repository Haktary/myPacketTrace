from scapy.all import *
from scapy.all import hexdump
import os
from pyfiglet import figlet_format
import six
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory


"""ajout des function pour l'autocompletion"""
function_completer = WordCompleter(
    [
        "hello",
        "exit",
        "all",
        "summary",
        "hexadecimal",
    ],
    ignore_case=True,
)
kb = KeyBindings()

@kb.add("c-space")
def _(event):
    b = event.app.current_buffer
    if b.complete_state:
        b.complete_next()
    else:
        b.start_completion(select_first=False)

try:
    from termcolor import colored
except ImportError:
    colored = None

def hello() :
    print('hello cli user')

def log(string, color, font="slant", figlet=False):
    if colored:
        if not figlet:
            six.print_(colored(string, color))
        else:
            six.print_(colored(figlet_format(
                string, font=font), color))
    else:
        six.print_(string)


def welcome() :
    log("my sniffing tools", color="blue", figlet=True)
    log("Welcome to my sniffing tools", "green")


def print_packet(packet):
    print(packet.show())


def print_summary(packet):
    print(packet.summary())

def print_hex(packet):
	packet.hexdump()

def get_command(cmd) :
    command = []
    try :
        command = cmd.split('(') 

    except :
        command[0] = cmd.strip(' ')

    return command

def get_argument(command) :
    arguments = []
    try : 
        args = command[1].split(')')[0].split(',') 
        n = 0
        while(len(args) > n ) :
            arg = args[n].split(' ')
            y = 0
            while(len(arg) > y) :
                if(arg[y] != '') :
                    arguments.append(arg[y])

                y = y + 1

            n = n + 1 
    except :
        pass

    return arguments


def parameters(nbparams, arguments) :
    if (len(arguments) > nbparams):
        log("error : too many input parameters", "red")
        return False
    else :
        return True

def command_line_function(command, arguments) :
    """l'ajout des nouvelle commandes ce passe dans cette fonction"""
    if (command.strip(' ') == 'hello') :
        if(parameters(0, arguments)) :
            hello()
    elif (command.strip(' ') == 'exit') :
        if(parameters(0, arguments)) :
            exit()
    elif (command.strip(' ') == 'all') :
    	if(parameters(1, arguments)) :
    		sniff(count=int(arguments[0]), prn=print_packet)
    elif (command.strip(' ') == 'summary') :
    	if(parameters(1, arguments)) :
    		sniff(count=int(arguments[0]), prn=print_summary)
    elif (command.strip(' ') == 'hexadecimal') :
    	if(parameters(1, arguments)) :
    		sniff(filter=ether, count=int(arguments[0]), prn=print_hex)
    else :
        log("error : command not found", "red")


def command_user():
    our_history = FileHistory(".history-file")
    session = PromptSession(history=our_history)  
    while(True) :
        res = six.print_(colored('cmd - : ', 'green'), end='')
        cmd = session.prompt(
            res,
            completer=function_completer,
            complete_while_typing=False,
            key_bindings=kb,
        )
        command = get_command(cmd)
        arguments = get_argument(command)
        
        command_line_function(command[0], arguments)

if __name__ == '__main__':
    welcome()
    command_user()