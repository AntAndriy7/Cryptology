import java.util.Arrays;

public class RC6 {

    private static final int W = 32;
    private static final int R = 20;
    private static final int P32 = 0xB7E15163;
    private static final int Q32 = 0x9E3779B9;

    private int[] S;

    public RC6(byte[] key) {
        create_key(key);
    }

    private void create_key(byte[] key) {
        int c = key.length / (W / 8);
        int[] L = new int[c];
        for (int i = 0; i < key.length; i++) {
            L[i / 4] = (L[i / 4] << 8) + (key[i] & 0xFF);
        }

        S = new int[2 * R + 4];
        S[0] = P32;
        for (int i = 1; i < S.length; i++) {
            S[i] = S[i - 1] + Q32;
        }

        int A = 0, B = 0, i = 0, j = 0;
        int v = 3 * Math.max(S.length, L.length);
        for (int s = 0; s < v; s++) {
            A = S[i] = rotate_left(S[i] + A + B, 3);
            B = L[j] = rotate_left(L[j] + A + B, (A + B) & 31);
            i = (i + 1) % S.length;
            j = (j + 1) % L.length;
        }
    }

    private int rotate_left(int value, int bits) {
        return (value << bits) | (value >>> (32 - bits));
    }

    private int rotate_right(int value, int bits) {
        return (value >>> bits) | (value << (32 - bits));
    }

    public void encrypt(int[] pt, int[] ct) {
        int A = pt[0];
        int B = pt[1];
        int C = pt[2];
        int D = pt[3];

        B += S[0];
        D += S[1];

        for (int i = 1; i <= R; i++) {
            int t = rotate_left(B * (2 * B + 1), 5);
            int u = rotate_left(D * (2 * D + 1), 5);
            A = rotate_left(A ^ t, u) + S[2 * i];
            C = rotate_left(C ^ u, t) + S[2 * i + 1];

            int temp = A; A = B; B = C; C = D; D = temp;
        }

        A += S[2 * R + 2];
        C += S[2 * R + 3];

        ct[0] = A;
        ct[1] = B;
        ct[2] = C;
        ct[3] = D;
    }

    public void decrypt(int[] ct, int[] pt) {
        int A = ct[0];
        int B = ct[1];
        int C = ct[2];
        int D = ct[3];

        C -= S[2 * R + 3];
        A -= S[2 * R + 2];

        for (int i = R; i >= 1; i--) {
            int temp = D; D = C; C = B; B = A; A = temp;

            int u = rotate_left(D * (2 * D + 1), 5);
            int t = rotate_left(B * (2 * B + 1), 5);
            C = rotate_right(C - S[2 * i + 1], t) ^ u;
            A = rotate_right(A - S[2 * i], u) ^ t;
        }

        D -= S[1];
        B -= S[0];

        pt[0] = A;
        pt[1] = B;
        pt[2] = C;
        pt[3] = D;
    }

    public static void main(String[] args) {
        byte[] key = "SecretKey1234567".getBytes();
        RC6 rc6 = new RC6(key);

        int[][] plaintexts = {
                {0x12345678, 0x9ABCDEF0, 0x0FEDCBA9, 0x87654321},
                {0x00112233, 0x44556677, 0x8899AABB, 0xCCDDEEFF},
                {0x0A1B2C3D, 0x4E5F6071, 0x8293A4B5, 0xC6D7E8F9}
        };

        for (int i = 0; i < plaintexts.length; i++) {
            int[] plaintext = plaintexts[i];
            int[] ciphertext = new int[4];
            int[] decrypted = new int[4];

            System.out.println("Plaintext " + (i + 1) + ": " + Arrays.toString(plaintext));

            rc6.encrypt(plaintext, ciphertext);
            System.out.println("Ciphertext " + (i + 1) + ": " + Arrays.toString(ciphertext));

            rc6.decrypt(ciphertext, decrypted);
            System.out.println("Decrypted " + (i + 1) + ": " + Arrays.toString(decrypted));
            System.out.println();
        }
    }
}
