int nat46_create(char *devname);
int nat46_destroy(char *devname);
int nat46_configure(char *devname, char *buf);
void nat46_destroy_all(void);
void nat64_show_all_configs(struct seq_file *m);
