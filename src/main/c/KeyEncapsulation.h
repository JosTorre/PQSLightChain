/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_openquantumsafe_KeyEncapsulation */

#ifndef _KEYENCAPSULATION_H_INCLUDED_
#define _KEYENCAPSULATION_H_INCLUDED_
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     org_openquantumsafe_KeyEncapsulation
 * Method:    create_KEM_new
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_org_openquantumsafe_KeyEncapsulation_create_1KEM_1new
  (JNIEnv *, jobject, jstring);

/*
 * Class:     org_openquantumsafe_KeyEncapsulation
 * Method:    free_KEM
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_openquantumsafe_KeyEncapsulation_free_1KEM
  (JNIEnv *, jobject);

/*
 * Class:     org_openquantumsafe_KeyEncapsulation
 * Method:    get_KEM_details
 * Signature: ()Lorg/openquantumsafe/KeyEncapsulation/KeyEncapsulationDetails;
 */
JNIEXPORT jobject JNICALL Java_org_openquantumsafe_KeyEncapsulation_get_1KEM_1details
  (JNIEnv *, jobject);

/*
 * Class:     org_openquantumsafe_KeyEncapsulation
 * Method:    generate_keypair
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL Java_org_openquantumsafe_KeyEncapsulation_generate_1keypair
  (JNIEnv *, jobject, jbyteArray, jbyteArray);

/*
 * Class:     org_openquantumsafe_KeyEncapsulation
 * Method:    encap_secret
 * Signature: ([B[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_openquantumsafe_KeyEncapsulation_encap_1secret
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     org_openquantumsafe_KeyEncapsulation
 * Method:    decap_secret
 * Signature: ([B[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_openquantumsafe_KeyEncapsulation_decap_1secret
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
