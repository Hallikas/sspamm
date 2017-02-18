# sspamm
Semi's Spam Milter (sendmail/postfix filter)

*** THIS IS WORK IN PROGRESS ***

My old Sspamm is really old, first version was released back in 2004.
Because I haven't heared that anyone is using it, I haven't done so much
releases for public.

Now I'm starting that all over again. I will rewrite everything from
scratch.


Better instructions are coming later, for now this is just notes for myself

How to get this work on OSX:
1) Install xcode and port
2) You need python libraries: sudo easy_install pydns
3) Get pymilter, compile and install
  git clone https://github.com/sdgathman/pymilter
  cd pymilter
  perl -pi -e 's|/usr/lib/libmilter|/opt/local/lib|' setup.py
  CPPFLAGS="-I/opt/local/include" LDFLAGS="-L/opt/local/lib" python setup.py build
  python setup.py install

... After this OSX should be available to run sspamm.py
