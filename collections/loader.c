// SPDX-License-Identifier: GPL-2.0
/* Loader/runner for the arena-backed Rust collections tests.
 *
 * Loads one BPF object, runs libarena's arena_buddy_reset (buddy_init)
 * once, then bpf_prog_test_run()s every SEC("syscall") program whose name
 * starts with "test_"; each must return 0. Exit code = number of failures.
 */
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int run_prog(struct bpf_program *prog, int *retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (err)
		return err;
	*retval = opts.retval;
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_program *prog, *reset = NULL;
	struct bpf_object *obj;
	int err, failures = 0, ran = 0, retval;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <obj.bpf.o>\n", argv[0]);
		return 2;
	}

	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj) {
		fprintf(stderr, "open failed\n");
		return 2;
	}
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load failed: %d\n", err);
		return 2;
	}

	bpf_object__for_each_program(prog, obj) {
		if (!strcmp(bpf_program__name(prog), "arena_buddy_reset"))
			reset = prog;
	}
	if (!reset) {
		fprintf(stderr, "no arena_buddy_reset program\n");
		return 2;
	}
	err = run_prog(reset, &retval);
	if (err || retval) {
		fprintf(stderr, "buddy_init failed: err=%d ret=%d\n", err, retval);
		return 2;
	}

	bpf_object__for_each_program(prog, obj) {
		const char *name = bpf_program__name(prog);

		if (strncmp(name, "test_", 5))
			continue;
		err = run_prog(prog, &retval);
		ran++;
		if (err || retval) {
			printf("FAIL %-24s err=%d ret=%d\n", name, err, retval);
			failures++;
		} else {
			printf("OK   %s\n", name);
		}
	}
	printf("%s: %d/%d passed\n", argv[1], ran - failures, ran);
	return failures;
}
