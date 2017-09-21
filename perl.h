#include <EXTERN.h>
#include <perl.h>

static PerlInterpreter *my_perl;

static SV *perl_RC;
static SV *perl_PID;
static SV *perl_W;
static SV *perl_R;
static SV *perl_DIR;
static SV *perl_MEM;
static SV *perl_OP;
static SV *perl_FD;
static SV *perl_FN;
static SV *perl_EXE;
static SV *perl_LEN;
static SV *perl__;
static GV *perl_OUT;

static int OUT_fd = -1;
static int last_out = -1;

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

static void parse_perl(int out, string &code) {
    switch (perl_flag) {
    case 'E':
    case 'e': {
        string wrapped_code = "sub _ {\n" + code + "\n;}";
        const char *perl_args[] = { "", "-Mfeature=:all", "-e", wrapped_code.c_str() };
        if (perl_parse(my_perl, xs_init, 3, (char **)perl_args, NULL))
            fatal("Perl parsing failed");
        break;
    }
    case 'M': {
        const char *perl_args[] = { "", code.c_str(), };
        if (perl_parse(my_perl, xs_init, 3, (char **)perl_args, NULL))
            fatal("Perl parsing failed");
        break;
    }
    default:
        fatal("Internal error: unsupported perl_flag");
    }

    string open_out = "open OUT, '>&" + to_string(out) + "' or die q(Unable to open OUT); select OUT; $|=1; fileno(OUT)";
    OUT_fd = SvIV(eval_pv(open_out.c_str(), 0));
    last_out = out;

    debug(4, "perl OUT_fd:%d, last_out:%d", OUT_fd, last_out);

    sv_setiv_mg(get_sv("|", GV_ADD), 1);

    if (perl_run(my_perl))
        fatal("Perl running failed");

    perl_RC  = SvREFCNT_inc(get_sv("RC" , GV_ADD));
    perl_PID = SvREFCNT_inc(get_sv("PID", GV_ADD));
    perl_W   = SvREFCNT_inc(get_sv("W"  , GV_ADD));
    perl_R   = SvREFCNT_inc(get_sv("R"  , GV_ADD));
    perl_DIR = SvREFCNT_inc(get_sv("DIR", GV_ADD));
    perl_MEM = SvREFCNT_inc(get_sv("MEM", GV_ADD));
    perl_OP  = SvREFCNT_inc(get_sv("OP" , GV_ADD));
    perl_FD  = SvREFCNT_inc(get_sv("FD" , GV_ADD));
    perl_FN  = SvREFCNT_inc(get_sv("FN" , GV_ADD));
    perl_EXE = SvREFCNT_inc(get_sv("EXE", GV_ADD));
    perl_LEN = SvREFCNT_inc(get_sv("LEN", GV_ADD));
    perl__   = SvREFCNT_inc(get_sv("_"  , GV_ADD));

}

static void
dump_perl(int out, Process &p, int fd, const string &op, long long rc, bool writting, long long mem, size_t len) {
    if (mem || perl_flag == 'E' || perl_flag == 'M') {

        debug(4, "perl OUT_fd:%d, out:%d, last_out:%d", OUT_fd, out, last_out);
        if (out != last_out) {
            dup2(out, OUT_fd);
            last_out = out;
        }

        sv_setiv_mg(perl_RC, rc);
        sv_setiv_mg(perl_PID, p.pid);
        SvSetMagicSV(perl_W, (writting ? &PL_sv_yes : &PL_sv_no));
        SvSetMagicSV(perl_R, (writting ? &PL_sv_no : &PL_sv_yes));
        sv_setpvn_mg(perl_DIR, (writting ? "W" : "R"), 1);
        sv_setiv_mg(perl_MEM, mem);
        sv_setpvn_mg(perl_OP, op.c_str(), op.length());
        sv_setiv_mg(perl_FD, fd);
        const string &fd_path = p.fd_path(fd);
        sv_setpvn_mg(perl_FN, fd_path.c_str(), fd_path.length());
        sv_setpvn_mg(perl_EXE, p.process_name.c_str(), p.process_name.length());
        sv_setiv_mg(perl_LEN, len);
        if (mem) {
            const unsigned char *data = read_proc_mem(p.pid, mem, len);
            sv_setpvn_mg(perl__, (char *)data, len);
        }
        else
            SvSetMagicSV(perl__, &PL_sv_undef);

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

static void
shutdown_perl() {
    perl_destruct(my_perl);
    perl_free(my_perl);
}

static void perl_sys_term() {
    PERL_SYS_TERM();
}

static void fd_close_perl(int fd) {
    debug(4, "forgetting fd %d, last_fd is %d", fd, last_out);
    if (last_out == fd) {
        last_out = -1;
    }
}
