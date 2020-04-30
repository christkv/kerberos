{
  'targets': [
    {
      'target_name': 'kerberos',
      'include_dirs': [ '<!(node -e "require(\'nan\')")' ],
      'sources': [
        'src/kerberos.cc'
      ],
      'conditions': [
        ['OS=="mac" or OS=="linux" or OS=="zos"', {
          'sources': [
            'src/unix/base64.cc',
            'src/unix/kerberos_gss.cc',
            'src/unix/kerberos_unix.cc'
          ],
          'link_settings': {
            'libraries': [
              '-lkrb5',
              '-lgssapi_krb5'
            ]
          }
        }],
        ['OS=="win"',  {
          'sources': [
            'src/win32/kerberos_sspi.cc',
            'src/win32/kerberos_win32.cc'
          ],
          'link_settings': {
            'libraries': [
              'crypt32.lib',
              'secur32.lib',
              'Shlwapi.lib'
            ]
          }
        }],
        ['OS=="mac"', {
          'cflags!': [ '-fno-exceptions' ],
          'cflags_cc!': [ '-fno-exceptions' ],
          'xcode_settings': {
            'GCC_ENABLE_CPP_RTTI': 'YES',
            'OTHER_CPLUSPLUSFLAGS' : [ '-std=c++11', '-stdlib=libc++' ],
            'OTHER_LDFLAGS': [ '-stdlib=libc++' ],
            'MACOSX_DEPLOYMENT_TARGET': "10.7"
          }
        }],
        ['OS=="zos"', {
          'include_dirs': [
            '$(KRB5_HOME)/include/',
            '$(KRB5_HOME)/include/gssapi/'
          ],
          'libraries': [
            '$(KRB5_HOME)/lib/libgssrpc.a',
            '$(KRB5_HOME)/lib/libgssapi_krb5.a',
            '$(KRB5_HOME)/lib/libkrb5.a',
            '$(KRB5_HOME)/lib/libk5crypto.a',
            '$(KRB5_HOME)/lib/libcom_err.a',
            '$(KRB5_HOME)/lib/libkrb5support.a'
          ],
          "libraries!": ["-lkrb5", "-lgssapi_krb5"]
        }]
      ]
    }
  ]
}
