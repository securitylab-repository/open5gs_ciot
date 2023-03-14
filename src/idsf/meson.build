# created by le linh
# based on pcf,ausf

libidsf_sources = files('''
    context.c
    event.c

    nnrf-handler.c
    nidsf-handler.c

    sbi-path.c
    idsf-sm.c

    init.c
'''.split())

libidsf = static_library('idsf',
    sources : libidsf_sources,
    dependencies : [libapp_dep,
                    libsbi_dep],
    install : false)

libidsf_dep = declare_dependency(
    link_with : libidsf,
    dependencies : [libapp_dep,
                    libsbi_dep])

idsf_sources = files('''
    app.c
    ../main.c
'''.split())

executable('open5gs-idsfd',
    sources : idsf_sources,
    c_args : '-DDEFAULT_CONFIG_FILENAME="@0@/idsf.yaml"'.format(open5gs_sysconfdir),
    include_directories : srcinc,
    dependencies : libidsf_dep,
    install_rpath : libdir,
    install : true)