package net.oslokrok.hook;

/** Shape of the result consumed by AppVerifier in PayPal 10.19.0. */
final class VerifierResult {
    private VerifierResult() {}

    static Object adjustRuntime(Object value) {
        if (!(value instanceof Object[])) return value;
        Object[] result = (Object[]) value;
        if (result.length != 5 || !(result[1] instanceof int[])) return value;
        int[] reference = (int[]) result[1];
        if (reference.length != 1) return value;
        return adjust(value, reference[0]);
    }

    static Object adjust(Object value, int expected) {
        if (!(value instanceof Object[])) return value;
        Object[] result = (Object[]) value;
        if (result.length != 5 || !(result[0] instanceof int[]) || !(result[1] instanceof int[])) return value;
        int[] actual = (int[]) result[0];
        int[] reference = (int[]) result[1];
        if (actual.length != 1 || reference.length != 1 || reference[0] != expected || actual[0] == expected) return value;
        Object[] copy = result.clone();
        copy[0] = new int[] {expected};
        return copy;
    }
}
