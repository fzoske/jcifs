package jcifs.executors;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.Config;

public class WorkManagerProvider {

    private static final Logger logger = LoggerFactory.getLogger(WorkManagerProvider.class);
    
    private static final Object mutex = new Object();
    private static volatile WorkManagerImpl instance;
    
    public static WorkManager getWorkManager() {
        if (instance == null) {
            synchronized (mutex) {
                if (instance == null) {
                    instance = new WorkManagerImpl();
                }
            }
        }
        return instance;
    }
    
    public static void shutdown() {
        if (instance != null) {
            instance.service.shutdown();
            instance.service.shutdownNow();
            instance = null;
        }
    }
    
    private static final class WorkManagerImpl implements WorkManager {
        
        private final ExecutorService service;
        
        WorkManagerImpl() {
            service = makeService();
        }
        
        private static ExecutorService makeService() {
            String className = Config.getProperty("executors.executorServiceClass", DefaultExecutorFactory.class.getName());
            ExecutorFactory factory = null;
            try {
                Class<?> clazz = Class.forName(className);
                if (ExecutorFactory.class.isAssignableFrom(clazz)) {
                    factory = (ExecutorFactory) clazz.newInstance();
                }
            } catch (Exception e) {
                logger.error("Provided executors.executorServiceClass[" + className + "] doesn't implement " + ExecutorFactory.class.getName() + ". Default executors factory will be used instead.");
            }
            if (factory == null) factory = new DefaultExecutorFactory();
            return factory.make();
        }

        public <T> Future<T> submit(Callable<T> task) {
            return service.submit(task);
        }

        public <T> Future<T> submit(Runnable task, T result) {
            return service.submit(task, result);
        }

        public Future<?> submit(Runnable task) {
            return service.submit(task);
        }

        public <T> List<Future<T>> invokeAll(Collection<Callable<T>> tasks) throws InterruptedException {
            return service.invokeAll(tasks);
        }

        public <T> List<Future<T>> invokeAll(Collection<Callable<T>> tasks, long timeout, TimeUnit unit) throws InterruptedException {
            return service.invokeAll(tasks, timeout, unit);
        }

        public <T> T invokeAny(Collection<Callable<T>> tasks) throws InterruptedException, ExecutionException {
            return service.invokeAny(tasks);
        }

        public <T> T invokeAny(Collection<Callable<T>> tasks, long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            return service.invokeAny(tasks, timeout, unit);
        }
        
        
        
    }
    
}
