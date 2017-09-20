#include <EXTERN.h>
#include <perl.h>

static PerlInterpreter *my_perl;

static SV *perl_RC;
static SV *perl_PID;
static SV *perl_W;
static SV *perl_R;
static SV *perl_MEM;
static SV *perl_OP;
static SV *perl_FD;
static SV *perl_FN;
static SV *perl_EXE;
static SV *perl__;

static void init_perl(int &argc, char **&argv, char **&env) {
    PERL_SYS_INIT3(&argc,&argv,&env);
    my_perl = perl_alloc();
    perl_construct(my_perl);
}

EXTERN_C void boot_DynaLoader (pTHX_ CV* cv);
EXTERN_C void
xs_init(pTHX) {
    const char *file = __FILE__;
    newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}

static void parse_perl(string &code) {
    string wrapped_code = "use feature q(:all);\nsub _ {\n" + code + "\n;}";
    const char *perl_args[] = { "", "-e", wrapped_code.c_str() };
    perl_parse(my_perl, xs_init, 3, (char **)perl_args, NULL);

    perl_RC  = SvREFCNT_inc(get_sv("RC" , GV_ADD));
    perl_PID = SvREFCNT_inc(get_sv("PID", GV_ADD));
    perl_W   = SvREFCNT_inc(get_sv("W"  , GV_ADD));
    perl_R   = SvREFCNT_inc(get_sv("E"  , GV_ADD));
    perl_MEM = SvREFCNT_inc(get_sv("MEM", GV_ADD));
    perl_OP  = SvREFCNT_inc(get_sv("OP" , GV_ADD));
    perl_FD  = SvREFCNT_inc(get_sv("FD" , GV_ADD));
    perl_FN  = SvREFCNT_inc(get_sv("FN" , GV_ADD));
    perl_EXE = SvREFCNT_inc(get_sv("EXE", GV_ADD));
    perl__   = SvREFCNT_inc(get_sv("_"  , GV_ADD));

}

static void
dump_perl(Process &p, int fd, const string &op, long long rc, bool writting, long long mem, size_t len) {
    if (mem || perl_flag == 'E') {
        sv_setiv(perl_RC, rc);
        sv_setiv(perl_PID, p.pid);
        sv_setsv(perl_W, (writting ? &PL_sv_yes : &PL_sv_no));
        sv_setsv(perl_R, (writting ? &PL_sv_no : &PL_sv_yes));
        sv_setiv(perl_MEM, mem);
        sv_setpvn(perl_OP, op.c_str(), op.length());
        sv_setiv(perl_FD, fd);
        const string &fd_path = p.fd_path(fd);
        sv_setpvn(perl_FN, fd_path.c_str(), fd_path.length());
        sv_setpvn(perl_EXE, p.process_name.c_str(), p.process_name.length());

        if (mem) {
            const unsigned char *data = read_proc_mem(p.pid, mem, len);
            sv_setpvn(perl__, (char *)data, len);
        }
        else
            sv_setsv(perl__, &PL_sv_undef);

        dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        call_pv("_", G_SCALAR);
        SPAGAIN;
        FREETMPS;
        LEAVE;
    }
}


