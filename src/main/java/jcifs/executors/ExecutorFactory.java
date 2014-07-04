package jcifs.executors;

import java.util.concurrent.ExecutorService;

public interface ExecutorFactory {

    ExecutorService make();
    
}
