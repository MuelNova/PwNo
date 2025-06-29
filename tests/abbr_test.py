from pwn import *

from pwno import *

context.log_level = "debug"
config.ATTACHMENT = "./pwn"


def testFrame():
    # test if get_instance() returns the same instance while in different stack frame
    print(">>> TESTING FRAME")
    testFrameSH = gen_sh()

    def send_here():
        _, my_sh = get_instance()
        assert my_sh == testFrameSH
        sl(b"0")

    send_here()
    testFrameSH.close()
    print(">>> FRAME TEST PASSED")


def testAbbr():
    # test if abbr works
    print(">>> TESTING ABBR")
    sh = gen_sh()
    my_sh_name, my_sh = get_instance()
    sl(b"0")
    assert my_sh == sh, f"sh is {sh} with PID {sh.proc.pid} but get_instance() returns "
    f"{(my_sh_name, my_sh)} with PID {my_sh.proc.pid})"
    sh.close()
    print(">>> ABBR TEST PASSED")


def testAbbrAfterClose():
    print(">>> TESTING ABBR AFTER CLOSE")
    sh = gen_sh()
    print(id(sh))
    old = sh
    sl(b"0")
    sh.close()

    sh = gen_sh()

    _, new = get_instance()

    assert id(old) != id(new), "get_instance() is still using the old instance"
    sl(b"0")
    sh.close()
    another_name = gen_sh()
    _, new_ = get_instance()
    assert id(new) != id(new_), (
        "get_instance() is still using the old instance without changing it's name"
    )
    sl(b"0")
    another_name.close()
    print(">>> ABBR AFTER CLOSE TEST PASSED")


def testCustomAbbr():
    # test if custom abbr works
    print(">>> TESTING CUSTOM ABBR")
    p = gen_sh()
    sh = gen_sh()

    my_sl = abbr(p.sendline)
    p_instance = get_instance("p")
    sh_instance = get_instance()

    assert p_instance != sh_instance, "get_instance() doesn't return two instances"
    my_sl(b"0")
    my_sl(b"1")
    sl(b"1")
    p.close()
    p = gen_sh()
    my_sl(b"2")
    assert p_instance != get_instance("p"), (
        "get_instance(name) doesn't return two different instances."
    )
    p.close()
    sh.close()
    print(">>> CUSTOM ABBR TEST PASSED")


def testAbbrRemote():
    sh = remote("localhost", 19919)
    sl(b"echo 1 > /dev/null")
    p = remote("localhost", 19919)
    sl(b"cat /flag")
    ia()


testFrame()
testAbbr()
testAbbrAfterClose()
testCustomAbbr()

testAbbrRemote()
