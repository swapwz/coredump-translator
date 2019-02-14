#! /usr/bin/python
# -*- coding:utf-8 -*-
"""
   Coredump Translator
   Author: matrix
   Date: 2019-02-14
"""

import pdb

import subprocess
import sys
import os
import errno


def safe_delete(filepath):
    """ wrapper for os.remove """
    try:
        os.remove(filepath)
    except OSError as err:
        # don't care the ENOENT error
        if err.errno != errno.ENOENT:
            raise


def run_cmd(command):
    """
    @arg1: command string
    @ret: the result of after running command
    """
    output = []
    with open("/dev/null") as null:
        proc = subprocess.Popen(command.split(), stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                stderr=null)
        while True:
            data = proc.stdout.readline()
            if data:
                output.append(data)
            else:
                break
    return output


class LoadMap(object):
    """ Represent a load address map """
    def __init__(self):
        self._start_addr = None
        self._end_addr = None
        self._flag = None
        self._path = None

    def __str__(self):
        ret = "Load Map:\r\n"
        fmt = "%-15s %-15s %-5s %-s\r\n"
        ret += fmt % ("Start Address", "End Address", "flag", "path")
        ret += fmt % (hex(self._start_addr), hex(self._end_addr), self._flag, self._path)
        return ret

    @property
    def start_addr(self):
        return self._start_addr

    @start_addr.setter
    def start_addr(self, v):
        self._start_addr = v

    @property
    def end_address(self):
        return self._end_addr

    @end_address.setter
    def end_address(self, v):
        self._end_addr = v

    @property
    def flag(self):
        return self._flag

    @flag.setter
    def flag(self, v):
        self._flag = v

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, v):
        if os.path.isfile(v):
            self._path = v
        else:
            lib_suffix = ".so"
            libname = v.split(lib_suffix)
            if len(libname) > 1:
                self._path = libname[0] + lib_suffix
            else:
                self._path = v


class CoreDump(object):
    """ Represents a coredump file """
    def __init__(self, core_file):
        self.core_file = core_file
        self.load_maps = []

    def load(self):
        quick_lookup_dict = dict()
        output = run_cmd("readelf -n %s" % self.core_file)
        new_map = None
        for v in output:
            items = v.split()
            if len(items) == 3 and items[0].strip().startswith("0x"):
                new_map = LoadMap()
                new_map.start_addr = int(items[0], 16)
                new_map.end_address = int(items[1], 16)

            if new_map and len(items) == 1:                
                new_map.path = items[0].strip()
                self.load_maps.append(new_map)
                quick_lookup_dict[new_map.start_addr] = new_map
                new_map = None

        # find the flag only have RE of the load address
        output = run_cmd("readelf -l %s" % self.core_file)
        start_address = None
        flag = None
        for v in output:
            items = v.split()
            if len(items) == 4 and items[2].startswith("0x"):
                start_address = int(items[2], 16)
                continue

            if start_address:
                if v.find("R E") != -1:
                    load_map = quick_lookup_dict.get(start_address)
                    if load_map:
                        load_map.flag = "RE"
                start_address = None

        self.load_maps = [ m for m in self.load_maps if m.flag == "RE" ]
        del quick_lookup_dict
        
    def find_map(self, address):
        for m in self.load_maps:
            if address >= m.start_addr and address <= m.end_address:
                return m
        return None


class GDBController(object):
    def __init__(self, core_file):
        self.raw_stack = []
        self.translated_strace = []
        self.symbols = {}
        self.core_file = core_file
        self.coredump = CoreDump(core_file)
        self.init()

    def init(self):
        self.coredump.load()
        self.init_rawstack()

    def init_rawstack(self):
        output_file = "/tmp/coretrans.%s" % os.getpid()
        gdb_script = "/tmp/coretrans.gdb.init.%s" % os.getpid()
        cmd = "set logging file %s\n" % output_file
        cmd += "core-file %s\n" % self.core_file
        cmd += "set logging on\n"
        cmd += "bt\nset logging off\nquit\n"

        try:
            with open(gdb_script, "w") as f:
                f.write(cmd)

            gdb_cmd = "gdb -x %s --batch-silent" % gdb_script
            run_cmd(gdb_cmd)

            with open(output_file, "r") as f:
                for line in f:
                    stack = line.split()
                    if stack[0].strip().startswith("#") and line.find("in ??") != -1:
                        self.raw_stack.append(int(stack[1], 16))
        except IOError:
            pass
        finally:
            safe_delete(gdb_script)
            safe_delete(output_file)

    def get_filetype(self, path):
        output = run_cmd("readelf -h %s" % path)
        for line in output:
            if line.find("Type:") != -1:
                items = line.split()
                return items[1]
        return None

    def add_symbol(self, path, load_addr):
        is_changed = False
        if path in self.symbols:
            return is_changed

        file_type = self.get_filetype(path)
        text_offset = None
        output = run_cmd("readelf -S %s" % path)
        for line in output:
            if line.find(".text") != -1:
                items = line.split()
                if len(items) == 5:
                    text_offset = int(items[3], 16)
                    if file_type == "DYN":
                        # dynamic object need relocation
                        self.symbols.setdefault(path, load_addr + text_offset)
                        is_changed = True
                    elif file_type == "EXEC":
                        self.symbols.setdefault(path, text_offset)
                        is_changed = True
                break
        return is_changed

    def update(self):
        output_file = "/tmp/coretrans.%s" % os.getpid()
        gdb_script = "/tmp/coretrans.gdb.init.%s" % os.getpid()
        cmd = "set logging file %s\n" % output_file
        cmd += "core-file %s\n" % self.core_file
        for path, text_addr in self.symbols.iteritems():
            cmd += "add-symbol-file %s %s\n" % (path, hex(text_addr))

        cmd += "set logging on\n"
        cmd += "info register\n"
        cmd += "bt\nset logging off\nquit\n"
        try:
            with open(gdb_script, "w") as f:
                f.write(cmd)
            gdb_cmd = "gdb -x %s --batch-silent" % gdb_script
            run_cmd(gdb_cmd)

            del self.translated_strace[:]
            del self.raw_stack[:]
            with open(output_file, "r") as f:
                for line in f:
                    stack = line.split()
                    if stack[0].strip().startswith("#"):
                        if line.find("in ??") != -1:
                            self.raw_stack.append(int(stack[1], 16))
                    self.translated_strace.append(line[:-1])
        except IOError:
            pass
        finally:
            safe_delete(output_file)
            safe_delete(gdb_script)

    def translate(self):
        try_again = False
        for raw_stack in self.raw_stack:
            m = self.coredump.find_map(raw_stack)
            if m and self.add_symbol(m.path, m.start_addr):
                try_again = True

        if try_again:
            self.update()
            self.translate()

    def show_stack(self):
        print("Exception Information:")
        if len(self.translated_strace) != 0:
            for strace in self.translated_strace:
                print(strace)
        else:
            print("\tNo exception found.")


# Entry point
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: %s <coredump filepath>" % sys.argv[0])
        sys.exit(1)
    try:
        core_filepath = sys.argv[1]
        if os.path.isfile(core_filepath):
            controller = GDBController(core_filepath)
            controller.translate()
            controller.show_stack()
            sys.exit(0)
        else:
            print("%s is invalid coredump file." % core_filepath)
            sys.exit(1)
    except Exception as e:
        print("Failed to translate coredump: %s", e)
        sys.exit(1)

