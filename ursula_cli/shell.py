#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2015, Craig Tracey <craigtracey@gmail.com>
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations

import argparse
import logging
import os
import shutil
import socket
import subprocess
import sys
import time
import yaml

LOG = logging.getLogger(__name__)
ANSIBLE_VERSION = '1.9.2-bbg'


def _initialize_logger(level=logging.DEBUG, logfile=None):
    global LOG
    LOG.setLevel(level)

    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(levelname)s: %(message)s")
    handler.setFormatter(formatter)
    LOG.addHandler(handler)


def _check_ansible_version():
    process = subprocess.Popen(
        ["ansible-playbook --version"], shell=True,
        stdout=subprocess.PIPE)
    output, _ = process.communicate()
    retcode = process.poll()
    if retcode:
        raise Exception("Error discovering ansible version")
    version_output = output.split('\n')[0]
    version = version_output.split(' ')[1]
    if not version == ANSIBLE_VERSION:
        raise Exception("You are using ansible-playbook '%s'. "
                        "Current required version is: '%s'. You may install "
                        "the correct version with 'pip install -U -r "
                        "requirements.txt'" % (version, ANSIBLE_VERSION))


def _append_envvar(key, value):
    if key in os.environ:
        os.environ[key] = "%s %s" % (os.environ[key], value)
    else:
        _set_envvar(key, value)


def _set_envvar(key, value):
    os.environ[key] = value


def _set_default_env():
    cm_path = os.path.expanduser('~/.ssh/controlmasters')
    if not os.path.exists(cm_path):
        os.makedirs(cm_path)

    _set_envvar('PYTHONUNBUFFERED', '1')  # needed in order to stream output
    _set_envvar('PYTHONIOENCODING', 'UTF-8')  # needed to handle stdin input
    _set_envvar('ANSIBLE_FORCE_COLOR', 'yes')
    _append_envvar('ANSIBLE_SSH_ARGS', '-o ControlMaster=auto')
    _append_envvar("ANSIBLE_SSH_ARGS",
                   "-o ControlPath=~/.ssh/controlmasters/u-%r@%h:%p")
    _append_envvar("ANSIBLE_SSH_ARGS", "-o ControlPersist=300")


def test_ssh(host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, 22))
    except Exception as e:
        return False
    return True


def _run_ansible(inventory, playbook, user='root', module_path='./library',
                 sudo=False, extra_args=[]):
    command = [
        'ansible-playbook',
        '--inventory-file',
        inventory,
        '--user',
        user,
        '--module-path',
        module_path,
        playbook,
    ]

    if sudo:
        command.append("--sudo")
    command += extra_args

    LOG.debug("Running command: %s with environment: %s",
              " ".join(command), os.environ)
    proc = subprocess.Popen(command, env=os.environ.copy(), shell=False,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)

    for line in iter(proc.stdout.readline, b''):
        print line.rstrip()

    proc.communicate()[0]
    return proc.returncode


def _vagrant_ssh_config(environment, boxes):
    ssh_config_file = ".vagrant/%s.ssh" % os.path.basename(environment)
    f = open(ssh_config_file, 'w')
    for box in boxes:
        command = [
            'vagrant',
            'ssh-config',
            box
        ]
        proc = subprocess.Popen(command, env=os.environ.copy(),
                                shell=False,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)

        for line in iter(proc.stdout.readline, b''):
            f.write("%s\n" % line.rstrip())

        if proc.returncode:
            raise Exception("Failed to write SSH config to %s"
                            % (ssh_config_file))
            return proc.returncode

    f.close()

    if 'not yet ready for SSH' in open(ssh_config_file).read():
        LOG.debug("waiting for Vagrant to be ready for SSH")
        time.sleep(5)
        _vagrant_ssh_config(environment, boxes)

    _append_envvar("ANSIBLE_SSH_ARGS", "-F %s" % ssh_config_file)

    return 0


def _ssh_add(keyfile):
    command = ["ssh-add", keyfile]
    proc = subprocess.Popen(command, env=os.environ.copy(),
                            shell=False,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)

    if proc.returncode:
        raise Exception("Failed to run %s with environment: %s"
                        % " ".join(command), os.environ)
        return proc.returncode


def _run_heat(args, hot):
    try:
        from heatclient.client import Client as Heat_Client
        from keystoneclient.v2_0 import Client as Keystone_Client
    except ImportError as e:
        LOG.error("You must have python-heatclient in your python path")
        raise Exception(e)

    CREDS = {
        'username': os.environ['OS_USERNAME'],
        'password': os.environ['OS_PASSWORD'],
        'tenant_name': os.environ['OS_TENANT_NAME'],
        'auth_url': os.environ['OS_AUTH_URL'],
    }

    stack_name = os.path.basename(args.environment)

    STACK = {
        'stack_name': stack_name,
        'template': hot
    }

    LOG.debug("Logging into heat")

    ks_client = Keystone_Client(**CREDS)
    heat_endpoint = ks_client.service_catalog.url_for(
        service_type='orchestration', endpoint_type='publicURL')
    heatclient = Heat_Client('1', heat_endpoint, token=ks_client.auth_token)

    try:
        LOG.debug("Checking for existence of heat stack: %s" % stack_name)
        heatclient.stacks.get(stack_name)
        stack_exists = True
        LOG.debug("Already exists")
    except Exception as e:
        if e.code == 404:
            stack_exists = False
        else:
            raise Exception(e)

    if not stack_exists:
        LOG.debug("Creating stack")
        heatclient.stacks.create(**STACK)
        time.sleep(5)
        while heatclient.stacks.get(stack_name).status == 'IN_PROGRESS':
            LOG.debug("Waiting on stack creation...")
            time.sleep(5)

    stack = heatclient.stacks.get(stack_name)
    if stack.status != 'COMPLETE':
        raise Exception("stack %s returned an unexpected status (%s)" %
                        (stack_name, stack.status))

    LOG.debug("Stack created!")

    servers = {}
    floating_ip = None
    for output in stack.outputs:
        if output['output_key'] == "floating_ip":
            floating_ip = output['output_value']
            LOG.debug("floating_ip : %s" % floating_ip)
        elif output['output_key'] == "private_key":
            private_key = output['output_value']
        else:
            servers[output['output_key']] = output['output_value']
            LOG.debug("server : %s (%s) " %
                      (output['output_key'], output['output_value']))

    LOG.debug("writing ssh_key to /tmp/ssh_key")
    with open("tmp/ssh_key", "w") as text_file:
        text_file.write(private_key)
    os.chmod("tmp/ssh_key", 0600)
    args.ursula_ssh_key = "tmp/ssh_key"

    ssh_config = """
Host *
  User ubuntu
  ForwardAgent yes
  UserKnownHostsFile /dev/null
  StrictHostKeyChecking no
  PasswordAuthentication no
  IdentityFile tmp/ssh_key
"""
    with open("tmp/ssh_config", "w") as text_file:
        text_file.write(ssh_config)

    if floating_ip:
        ssh_config_pre = """
Host floating_ip
  Hostname {floating_ip}
"""
        ssh_config = ssh_config_pre.format(floating_ip=floating_ip)
        with open("tmp/ssh_config", "a") as text_file:
            text_file.write(ssh_config)
        _ssh_add("tmp/ssh_key")

    for server, ip in servers.iteritems():
        test_ip = ip
        ssh_config_pre = """
Host {server}
  Hostname {ip}
"""
        if floating_ip:
            ssh_config_pre += ("  ProxyCommand ssh -o StrictHostKeyChecking=no"
                               " ubuntu@{floating_ip} nc %h %p\n\n")
        ssh_config = ssh_config_pre.format(
            server=server, ip=ip, floating_ip=floating_ip)
        with open("tmp/ssh_config", "a") as text_file:
            text_file.write(ssh_config)

    ansible_ssh_config_file = "tmp/ssh_config"
    if os.path.isfile(ansible_ssh_config_file):
        _append_envvar("ANSIBLE_SSH_ARGS", "-F %s" % ansible_ssh_config_file)

    LOG.debug("waiting for SSH connectivity...")
    if floating_ip:
        while not test_ssh(floating_ip):
            LOG.debug("waiting for SSH connectivity...")
            time.sleep(5)
    else:
        while not test_ssh(test_ip):
            LOG.debug("waiting for SSH connectivity...")
            time.sleep(5)


def _vagrant_copy_yml(environment):
    src = "%s/vagrant.yml" % environment
    dest = ".vagrant/vagrant.yml"
    shutil.copy2(src, dest)


def _run_vagrant(environment):
    vagrant_config_file = "%s/vagrant.yml" % environment

    if os.path.isfile(vagrant_config_file):
        _set_envvar("SETTINGS_FILE", vagrant_config_file)
        vagrant_config = yaml.load(open(vagrant_config_file, 'r'))
    else:
        vagrant_config = yaml.load(open('vagrant.yml', 'r'))

    vms = vagrant_config['vms'].keys()

    command = [
        'vagrant',
        'up',
        '--no-provision',
    ] + vagrant_config['vms'].keys()

    LOG.debug("Running command: %s\nEnvs:%s", " ".join(command), os.environ)
    proc = subprocess.Popen(command, env=os.environ.copy(),
                            shell=False,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)

    for line in iter(proc.stdout.readline, b''):
        print line.rstrip()

    if proc.returncode:
        raise Exception("Failed to run %s with environment: %s"
                        % " ".join(command), os.environ)
        return proc.returncode
    else:

        print "**************************************************"
        print "Ursula <3 Vagrant"
        print "To interact with your environment via Vagrant set:"
        print "$ export SETTINGS_FILE=%s" % vagrant_config_file
        print "**************************************************"

        rc = _vagrant_ssh_config(environment, vms)
        if rc:
            return rc

    return 0


def run(args, extra_args):
    _set_default_env()

    if not os.path.exists(args.environment):
        raise Exception("Environment '%s' does not exist", args.environment)

    _set_envvar('URSULA_ENV', os.path.abspath(args.environment))

    inventory = os.path.join(args.environment, 'hosts')
    if not os.path.exists(inventory) or not os.path.isfile(inventory):
        raise Exception("Inventory file '%s' does not exist" % inventory)

    # Try 2.0 first, fall back to unversioned defaults
    ansible_var_defaults_file = os.path.join(args.environment,
                                             '../defaults-2.0.yml')
    if not os.path.isfile(ansible_var_defaults_file):
    ansible_var_defaults_file = os.path.join(args.environment,
                                             '../defaults.yml')
    if os.path.isfile(ansible_var_defaults_file):
        _append_envvar("ANSIBLE_VAR_DEFAULTS_FILE", ansible_var_defaults_file)

    if args.ursula_ssh_config:
        ansible_ssh_config_file = args.ursula_ssh_config
    else:
        ansible_ssh_config_file = os.path.join(args.environment, 'ssh_config')
    if os.path.isfile(ansible_ssh_config_file):
        _append_envvar("ANSIBLE_SSH_ARGS", "-F %s" % ansible_ssh_config_file)

    if args.ursula_forward:
        _append_envvar("ANSIBLE_SSH_ARGS", "-o ForwardAgent=yes")

    if args.ursula_test:
        extra_args += ['--syntax-check', '--list-tasks']

    if args.provisioner == "vagrant":
        if os.path.exists('envs/example/vagrant.yml'):
            if os.path.isfile('envs/example/vagrant.yml'):
                extra_args += ['--extra-vars', '@envs/example/vagrant.yml']
        rc = _run_vagrant(environment=args.environment)
        if rc:
            return rc
        _vagrant_copy_yml(args.environment)
        if not args.ursula_user:
            args.ursula_user = "vagrant"
        if not args.ursula_sudo:
            args.ursula_sudo = True
    if args.provisioner == "heat":
        heat_file = "%s/heat_stack.yml" % args.environment
        if not os.path.exists(heat_file):
            raise Exception(
                "heat provider requires a heat file at %s" % heat_file)
        with open(heat_file, "r") as myfile:
            hot = myfile.read()
        heat_extra_args = "%s/vars_heat.yml" % args.environment
        if os.path.exists(heat_extra_args) and os.path.isfile(heat_extra_args):
            extra_args += ['--extra-vars', '@%s' % heat_extra_args]
        rc = _run_heat(args=args, hot=hot)
        if rc:
            return rc
        if not args.ursula_user:
            args.ursula_user = "ubuntu"
        if not args.ursula_sudo:
            args.ursula_sudo = True
    else:
        if not args.ursula_user:
            args.ursula_user = "root"
    rc = _run_ansible(inventory, args.playbook, extra_args=extra_args,
                      user=args.ursula_user, sudo=args.ursula_sudo)
    return rc


def main():
    parser = argparse.ArgumentParser(description='A CLI wrapper for ansible')
    parser.add_argument('environment', help='The environment you want to use')
    parser.add_argument('playbook', help='The playbook to run')
    # any args should be namespaced --ursula-$SOMETHING so as not to conflict
    # with ansible-playbook's command line parameters
    parser.add_argument(
        '--ursula-user', help='The user to run as', default=None)
    parser.add_argument('--ursula-ssh-config', help='path to your ssh config')
    parser.add_argument('--ursula-forward', action='store_true',
                        help='The playbook to run')
    parser.add_argument('--ursula-test', action='store_true',
                        help='Test syntax for playbook')
    parser.add_argument('--ursula-debug', action='store_true',
                        help='Run this tool in debug mode')
    parser.add_argument('--provisioner',
                        help='The external provisioner to use',
                        default=None, choices=["vagrant", "heat"])
    parser.add_argument('--vagrant', action='store_true',
                        help='Provision environment in vagrant')
    parser.add_argument('--ursula-sudo', action='store_true',
                        help='Enable sudo')

    args, extra_args = parser.parse_known_args()
    try:
        log_level = logging.INFO
        if args.ursula_debug:
            log_level = logging.DEBUG
        _initialize_logger(log_level)
        if args.vagrant:
            LOG.warn("--vagrant is depreciated, use --provisioner=vagrant")
            args.provisioner = "vagrant"
        _check_ansible_version()
        rc = run(args, extra_args)
        sys.exit(rc)
    except Exception as e:
        LOG.error(e)
        sys.exit(-1)


if __name__ == '__main__':
    main()
