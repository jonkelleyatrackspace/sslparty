#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         sslcheckopt.py
# Purpose:      Gives you a config index to set the shared_settings for the
#               ssl configs.

# Just run this command with -h, and build the sample config, then update the daemons configs!

from time import time
from multiprocessing import Process, JoinableQueue
from xml.etree.ElementTree import Element, tostring
from xml.dom import minidom
import sys

from plugins import PluginsFinder

try:
    from utils.CommandLineParser import CommandLineParser, CommandLineParsingError
    from utils.ServersConnectivityTester import ServersConnectivityTester
except ImportError:
    print '\nERROR: Could not import nassl Python module. Did you clone SSLyze\'s repo ? \n' +\
    'Please download the right pre-compiled package as described in the README.'
    sys.exit()


PROJECT_VERSION = 'SSLyze v0.7'
PROJECT_URL = "https://github.com/isecPartners/sslyze"
PROJECT_EMAIL = 'sslyze@isecpartners.com'
PROJECT_DESC = 'Fast and full-featured SSL scanner'


# Todo: Move formatting stuff to another file
SCAN_FORMAT = 'Scan Results For {0}:{1} - {2}:{1}'


class WorkerProcess(Process):

    def __init__(self, queue_in, queue_out, available_commands, shared_settings):
        Process.__init__(self)
        self.queue_in = queue_in
        self.queue_out = queue_out
        self.available_commands = available_commands
        self.shared_settings = shared_settings

    def run(self):
        """
        The process will first complete tasks it gets from self.queue_in.
        Once it gets notified that all the tasks have been completed,
        it terminates.
        """
        from plugins.PluginBase import PluginResult    
        # Plugin classes are unpickled by the multiprocessing module
        # without state info. Need to assign shared_settings here
        for plugin_class in self.available_commands.itervalues():
            plugin_class._shared_settings = self.shared_settings
        
        while True:

            task = self.queue_in.get() # Grab a task from queue_in

            if task == None: # All the tasks have been completed
                self.queue_out.put(None) # Pass on the sentinel to result_queue
                self.queue_in.task_done()
                break

            (target, command, args) = task
            # Instatiate the proper plugin
            plugin_instance = self.available_commands[command]()
                
            try: # Process the task
                result = plugin_instance.process_task(target, command, args)
            except Exception as e: # Generate txt and xml results
                #raise
                txt_result = ['Unhandled exception when processing --' + 
                              command + ': ', str(e.__class__.__module__) + 
                              '.' + str(e.__class__.__name__) + ' - ' + str(e)]
                xml_result = Element(command, exception=txt_result[1])
                result = PluginResult(txt_result, xml_result)

            # Send the result to queue_out
            self.queue_out.put((target, command, result))
            self.queue_in.task_done()

        return


def _format_title(title):
    return ' ' + title.upper()+ '\n' + ' ' + ('-' * len(title))


def _format_xml_target_result(target, result_list):
    (host, ip, port, sslVersion) = target
    target_xml = Element('target', host=host, ip=ip, port=str(port))
    result_list.sort(key=lambda result: result[0]) # Sort results
    
    for (command, plugin_result) in result_list:
        target_xml.append(plugin_result.get_xml_result())

    return target_xml


def _format_txt_target_result(target, result_list):
    (host, ip, port, sslVersion) = target
    target_result_str = ''

    for (command, plugin_result) in result_list:
        # Print the result of each separate command
        target_result_str += '\n'
        for line in plugin_result.get_txt_result():
            target_result_str += line + '\n'
    
    scan_txt = SCAN_FORMAT.format(host, str(port), ip)
    return _format_title(scan_txt) + '\n' + target_result_str + '\n\n'


def main():

    #--PLUGINS INITIALIZATION--
    start_time = time()
    print '\n\n\n' + _format_title('Registering available plugins')
    sslyze_plugins = PluginsFinder()
    available_plugins = sslyze_plugins.get_plugins()
    available_commands = sslyze_plugins.get_commands()
    print ''
    for plugin in available_plugins:
        print '  ' + plugin.__name__
    print '\n\n'

    # Create the command line parser and the list of available options
    sslyze_parser = CommandLineParser(available_plugins, PROJECT_VERSION)

    try: # Parse the command line
        (command_list, target_list, shared_settings) = sslyze_parser.parse_command_line()
    except CommandLineParsingError as e:
        print e.get_error_msg()
        return

    print shared_settings


if __name__ == "__main__":
    main()
