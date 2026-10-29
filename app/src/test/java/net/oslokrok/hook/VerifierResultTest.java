package net.oslokrok.hook;

import org.junit.Test;
import static org.junit.Assert.*;

public class VerifierResultTest {
    @Test public void correctsMismatchWithoutChangingOriginalOrOtherFields() {
        Object marker = new Object();
        Object[] input = {new int[] {4}, new int[] {7}, marker, new int[] {2}, null};
        Object[] output = (Object[]) VerifierResult.adjust(input, 7);
        assertNotSame(input, output);
        assertEquals(7, ((int[]) output[0])[0]);
        assertEquals(4, ((int[]) input[0])[0]);
        assertSame(input[1], output[1]);
        assertSame(marker, output[2]);
        assertSame(input[3], output[3]);
    }

    @Test public void ignoresUnexpectedAndAlreadyMatchingResults() {
        Object[] matching = {new int[] {7}, new int[] {7}, null, null, null};
        Object[] wrongReference = {new int[] {4}, new int[] {8}, null, null, null};
        Object[] wrongShape = {new int[] {4}, new int[0], null, null, null};
        assertSame(matching, VerifierResult.adjust(matching, 7));
        assertSame(wrongReference, VerifierResult.adjust(wrongReference, 7));
        assertSame(wrongShape, VerifierResult.adjust(wrongShape, 7));
        assertNull(VerifierResult.adjust(null, 7));
    }

    @Test public void runtimeResultUsesSecondValueAndLeavesMalformedResultsAlone() {
        Object[] input = {new int[] {5}, new int[] {900}, null, new int[] {3}, new String[] {"test"}};
        Object[] output = (Object[]) VerifierResult.adjustRuntime(input);
        assertEquals(900, ((int[]) output[0])[0]);
        assertEquals(5, ((int[]) input[0])[0]);
        assertSame(input[4], output[4]);
        Object[] malformed = {new int[] {5}, null, null, null, null};
        assertSame(malformed, VerifierResult.adjustRuntime(malformed));
        assertNull(VerifierResult.adjustRuntime(null));
    }
}
