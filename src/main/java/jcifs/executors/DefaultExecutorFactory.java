package jcifs.executors;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import jcifs.Config;

public class DefaultExecutorFactory implements ExecutorFactory {

    @Override
    public ExecutorService make() {
        int maxThreadCount = Config.getInt("jcifs.executors.threads.count", 100);
        int coreThreadCount = Config.getInt("jcifs.executors.threads.core.count", 0);
        long keepAliveTime = Config.getLong("jcifs.executors.threads.keepAliveTimeMillis", TimeUnit.SECONDS.toMillis(60));
        return new ThreadPoolExecutor(coreThreadCount, maxThreadCount,
                                      keepAliveTime, TimeUnit.MILLISECONDS,
                                      new SynchronousQueue<Runnable>());
    }

}
