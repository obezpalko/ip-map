#!/usr/bin/env python


if __name__ == '__main__':
    import amazon, IANA
    print('Ok')
    print(IANA.Networks().get())
    print(amazon.Networks().get())
