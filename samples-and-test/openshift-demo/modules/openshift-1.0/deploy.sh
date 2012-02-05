play build-module
cp dist/openshift-1.0.zip /home/sas/devel/apps/playdoces/public/repo
play gae:deploy /home/sas/devel/apps/playdoces/ --gae=$GAE_PATH

